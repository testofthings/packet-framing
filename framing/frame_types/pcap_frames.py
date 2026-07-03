"""PCAP frame definitions and related types"""

import pathlib
from typing import Iterable, Optional, Iterator

from framing.base import Frame, LayerMapping
from framing.codecs import IntegerFormat
from framing.fields import Structure, Sequence, ValueOf
from framing.frame_types.ethernet_frames import EthernetII, Ethernet_Payloads
from framing.frame_types.ipv6_frames import ip_frame_type
from framing.frames import Frames
from framing.layer_stack import StackLayer, StackState
from framing.raw_data import Raw, RawData

# https://datatracker.ietf.org/doc/id/draft-gharris-opsawg-pcap-00.html


# pylint: disable=invalid-name


Int = IntegerFormat().big_endian()  # big endian integers

# PCAP link-layer header types
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101


class FileHeader(Frame):
    """PCAP file header"""
    structure = Structure['FileHeader']()

    Magic_Number = structure.raw(bytes=4, default=Raw.hex("D4C3B2A1"))
    Major_Version = structure.integer(Int.bytes(2), default=2)
    Minor_Version = structure.integer(Int.bytes(2), default=4)
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

    @classmethod
    def open_file(cls, file: pathlib.Path, mappings: Optional[LayerMapping]) -> 'PCAPFile':
        """Open and dissect a PCAP file"""
        f = PCAPFile(Frames.dissect_file(file))
        return mappings.add_to(f) if mappings else f


# Define PCAP payload type mappings
PCAP_Payloads = LayerMapping(PacketRecord.Packet_Data).by(PCAPFile.File_Header / FileHeader.LinkType, {
    LINKTYPE_ETHERNET: EthernetII,
})


def frame_for_link_type(link_type: int, data: RawData) -> Frame:
    """Top frame for a record, Ethernet or raw IPv4/IPv6."""
    if data.byte_length() == 0:
        raise ValueError("Empty packet data")
    if link_type == LINKTYPE_ETHERNET:
        return EthernetII(Frames.dissect(data, mappings=Ethernet_Payloads))
    if link_type == LINKTYPE_RAW:
        return ip_frame_type(data)(Frames.dissect(data))
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
        file = PCAPFile(Frames.dissect(state.data))
        hdr = PCAPFile.File_Header[file]
        pay_type = FileHeader.LinkType[hdr]
        state = state.add(file)
        for rec in PCAPRecordIterator(file):
            pay_data = PacketRecord.Packet_Data[rec]
            n_state = state.add(rec, pay_type, pay_data)
            yield n_state
