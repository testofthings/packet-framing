"""PCAP frame definitions and related types"""

import pathlib
from typing import Iterable, Optional, Iterator

from framing.base import Frame, LayerMapping
from framing.codecs import IntegerFormat
from framing.fields import Structure, Sequence, ValueOf
from framing.frame_types.ethernet_frames import EthernetII, Ethernet_Payloads
from framing.frame_types.ipv6_frames import ip_frame_type, IPv6_Payloads
from framing.frame_types.llc_frames import LLC_Payloads
from framing.frame_types.wifi_frames import MACFrame, WiFi_Payloads
from framing.frames import Frames
from framing.layer_stack import StackLayer, StackState
from framing.raw_data import Raw, RawData

# https://datatracker.ietf.org/doc/id/draft-gharris-opsawg-pcap-00.html


# pylint: disable=invalid-name


# PCAP integers are least significant octet first, unless the magic number tells otherwise
Int = IntegerFormat(lsb_first=True).swappable()

# PCAP file magic numbers, the first four octets of a file
MAGIC_NUMBER = Raw.hex("D4C3B2A1")                  # least significant octet first, microsecond timestamps
MAGIC_NUMBER_NANOSECONDS = Raw.hex("4D3CB2A1")      # least significant octet first, nanosecond timestamps
MAGIC_NUMBER_MSB = Raw.hex("A1B2C3D4")              # most significant octet first, microsecond timestamps
MAGIC_NUMBER_MSB_NANOSECONDS = Raw.hex("A1B23C4D")  # most significant octet first, nanosecond timestamps
MAGIC_NUMBER_PCAPNG = Raw.hex("0A0D0D0A")           # PCAPNG Section Header Block

# The PCAP file format versions we can read. A new minor version may add things a reader of an older
# version cannot handle, so newer minor versions are not read, which is what libpcap does, too.
# Versions older than 2.3 have the Captured and Original Packet Length fields interchanged.
MAJOR_VERSION = 2
MINOR_VERSION = 4
MINOR_VERSION_OLDEST = 3

# PCAP link-layer header types
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_IEEE802_11 = 105


def is_msb_first(data: RawData) -> bool:
    """Is the PCAP file data most significant octet first? Told by the magic number."""
    return data.sub_block(0, 4) in (MAGIC_NUMBER_MSB, MAGIC_NUMBER_MSB_NANOSECONDS)


class FileHeader(Frame):
    """PCAP file header"""
    structure = Structure['FileHeader']()

    Magic_Number = structure.raw(bytes=4, default=MAGIC_NUMBER)
    Major_Version = structure.integer(Int.bytes(2), default=MAJOR_VERSION)
    Minor_Version = structure.integer(Int.bytes(2), default=MINOR_VERSION)
    Reserved1 = structure.raw(bytes=4)
    Reserved2 = structure.raw(bytes=4)
    SnapLen = structure.integer(Int.bytes(4))
    LinkType = structure.integer(Int.bytes(4))


class PacketRecord(Frame):
    """PCAP packet record"""
    structure = Structure['PacketRecord']()

    Timestamp = structure.integer(Int.bytes(4))
    Timestamp_2 = structure.integer(Int.bytes(4))
    Captured_Packet_length = structure.integer(Int.bytes(4))
    Original_Packet_length = structure.integer(Int.bytes(4))
    Packet_Data = structure.raw().length_by(ValueOf(Captured_Packet_length).copy_to(Original_Packet_length))


class PCAPFile(Frame):
    """PCAP file"""
    structure = Structure['PCAPFile']()

    File_Header = structure.sub(FileHeader)
    Packet_Records = Sequence(structure.sub(PacketRecord))

    def check_format(self) -> 'PCAPFile':
        """Check that this is a PCAP file in the supported byte order and version.
        Raises ValueError, if it is not."""
        try:
            hdr = PCAPFile.File_Header[self]
            magic = FileHeader.Magic_Number[hdr]
            major, minor = FileHeader.Major_Version[hdr], FileHeader.Minor_Version[hdr]
        except EOFError as e:
            raise ValueError("The file is too short to be a PCAP file") from e
        if magic == MAGIC_NUMBER_PCAPNG:
            raise ValueError("The file is in PCAPNG format, which is not supported")
        if magic not in (MAGIC_NUMBER, MAGIC_NUMBER_NANOSECONDS,
                         MAGIC_NUMBER_MSB, MAGIC_NUMBER_MSB_NANOSECONDS):
            raise ValueError(f"Not a PCAP file, the magic number is {magic.to_hex()}")
        if major != MAJOR_VERSION or not MINOR_VERSION_OLDEST <= minor <= MINOR_VERSION:
            raise ValueError(f"Unsupported PCAP file version {major}.{minor}, versions "
                             f"{MAJOR_VERSION}.{MINOR_VERSION_OLDEST} to {MAJOR_VERSION}.{MINOR_VERSION} "
                             "are supported")
        return self

    @classmethod
    def open_file(cls, file: pathlib.Path, mappings: Optional[LayerMapping]) -> 'PCAPFile':
        """Open and dissect a PCAP file"""
        data = Raw.file(file)
        f = PCAPFile(Frames.dissect(data, int_swap=is_msb_first(data)))
        return Frames.check_file(f, PCAPFile.check_format, mappings)


# Define PCAP payload type mappings
PCAP_Payloads = LayerMapping(PacketRecord.Packet_Data).by(PCAPFile.File_Header / FileHeader.LinkType, {
    LINKTYPE_ETHERNET: EthernetII,
    LINKTYPE_IEEE802_11: MACFrame,
})


def frame_for_link_type(link_type: int, data: RawData) -> Frame:
    """Top frame for a record, Ethernet or raw IPv4/IPv6."""
    if data.byte_length() == 0:
        raise ValueError("Empty packet data")
    if link_type == LINKTYPE_ETHERNET:
        return EthernetII(Frames.dissect(data, mappings=Ethernet_Payloads + IPv6_Payloads))
    if link_type == LINKTYPE_IEEE802_11:
        return MACFrame(Frames.dissect(data, mappings=WiFi_Payloads + LLC_Payloads + IPv6_Payloads))
    if link_type == LINKTYPE_RAW:
        return ip_frame_type(data)(Frames.dissect(data, mappings=IPv6_Payloads))
    raise ValueError(f"Unsupported LinkType {link_type}")


class PCAPRecordIterator(Iterator[PacketRecord]):
    """Record iterator"""
    def __init__(self, file: PCAPFile):
        self.source = PCAPFile.Packet_Records.iterate(file)

    def __next__(self) -> PacketRecord:
        return self.source.__next__()


class PCAPStackLayer(StackLayer):
    """PCAP stack layer"""
    def __init__(self) -> None:
        super().__init__(PCAPFile)

    def receive(self, state: StackState) -> Iterable[StackState]:
        file = PCAPFile(Frames.dissect(state.data, int_swap=is_msb_first(state.data))).check_format()
        hdr = PCAPFile.File_Header[file]
        pay_type = FileHeader.LinkType[hdr]
        state = state.add(file)
        for rec in PCAPRecordIterator(file):
            pay_data = PacketRecord.Packet_Data[rec]
            n_state = state.add(rec, pay_type, pay_data)
            yield n_state
