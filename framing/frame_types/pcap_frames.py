import pathlib
from typing import Iterable, Optional, Iterator

from framing.base import Frame, LayerMapping
from framing.codecs import IntegerFormat
from framing.fields import Structure, Sequence, ValueOf
from framing.frame_types.ethernet_frames import EthernetII
from framing.frames import Frames
from framing.layer_stack import StackLayer, StackState
from framing.raw_data import Raw

# https://datatracker.ietf.org/doc/id/draft-gharris-opsawg-pcap-00.html

Int = IntegerFormat().big_endian()  # big endian integers


class FileHeader(Frame):
    structure = Structure['FileHeader']()

    Magic_Number = structure.raw(bytes=4, default=Raw.hex("D4C3B2A1"))
    Major_Version = structure.integer(Int.bytes(2), default=2)
    Minor_Version = structure.integer(Int.bytes(2), default=4)
    Reserved1 = structure.raw(bytes=4)
    Reserved2 = structure.raw(bytes=4)
    SnapLen = structure.integer(Int.bytes(4))
    LinkType = structure.integer(Int.bytes(4))


class PacketRecord(Frame):
    structure = Structure['PacketRecord']()

    Timestamp = structure.integer(Int.bytes(4))
    Timestamp_2 = structure.integer(Int.bytes(4))
    Captured_Packet_length = structure.integer(Int.bytes(4))
    Original_Packet_length = structure.integer(Int.bytes(4))
    Packet_Data = structure.raw().length_by(ValueOf(Captured_Packet_length).copy_to(Original_Packet_length))


class PCAPFile(Frame):
    structure = Structure['PCAPFile']()

    File_Header = structure.sub(FileHeader)
    Packet_Records = Sequence(structure.sub(PacketRecord))

    @classmethod
    def open_file(cls, file: pathlib.Path, mappings: Optional[LayerMapping]) -> 'PCAPFile':
        f = PCAPFile(Frames.dissect_file(file))
        return mappings.add_to(f) if mappings else f


# Define PCAP payload type mappings
PCAP_Payloads = LayerMapping(PacketRecord.Packet_Data).by(PCAPFile.File_Header / FileHeader.LinkType, {
    1: EthernetII,
})


class PCAPRecordIterator(Iterator[PacketRecord]):
    """Record iterator"""
    def __init__(self, file: PCAPFile):
        self.source = PCAPFile.Packet_Records.iterate(file)

    def __next__(self) -> PacketRecord:
        return self.source.__next__()


class PCAPStackLayer(StackLayer):
    """PCAP stack layer"""
    def __init__(self):
        super().__init__(PCAPFile)

    def receive(self, state: StackState) -> Iterable[StackState]:
        file = PCAPFile(Frames.dissect(state.data))
        hdr = PCAPFile.File_Header[file]
        pay_type = FileHeader.LinkType[hdr]
        state = state.add(file)
        for i, rec in enumerate(PCAPRecordIterator(file)):
            pay_data = PacketRecord.Packet_Data[rec]
            n_state = state.add(rec, pay_type, pay_data)
            yield n_state
