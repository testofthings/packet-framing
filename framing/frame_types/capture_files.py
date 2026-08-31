"""Capture files, PCAP and PCAPNG, told apart by the magic number of the file data"""

import pathlib
from typing import Iterable, Iterator, Optional, Tuple, Type, Union

from framing.base import Frame, LayerMapping
from framing.frame_types.pcap_frames import (
    FileHeader, PCAPFile, PCAPRecordIterator, PCAPStackLayer, PacketRecord,
    MAGIC_NUMBER, MAGIC_NUMBER_MSB, MAGIC_NUMBER_MSB_NANOSECONDS, MAGIC_NUMBER_NANOSECONDS,
)
from framing.frame_types.pcapng_frames import (
    PCAPNGFile, PCAPNGPacketIterator, PCAPNGStackLayer, packet_data,
    MAGIC_NUMBER as MAGIC_NUMBER_PCAPNG,
)
from framing.layer_stack import StackLayer, StackState
from framing.raw_data import Raw, RawData


# pylint: disable=invalid-name


# Either a PCAP or a PCAPNG file
CaptureFile = Union[PCAPFile, PCAPNGFile]

PCAP_MAGIC_NUMBERS = (MAGIC_NUMBER, MAGIC_NUMBER_NANOSECONDS,
                      MAGIC_NUMBER_MSB, MAGIC_NUMBER_MSB_NANOSECONDS)


def capture_file_type(data: RawData) -> Type[Frame]:
    """The capture file frame type of the data, told by the magic number"""
    magic = data.sub_block(0, 4)
    if magic == MAGIC_NUMBER_PCAPNG:
        return PCAPNGFile
    if magic in PCAP_MAGIC_NUMBERS:
        return PCAPFile
    raise ValueError(f"Not a PCAP or PCAPNG file, the magic number is {magic.to_hex()}")


def open_capture_file(file: pathlib.Path, mappings: Optional[LayerMapping] = None) -> CaptureFile:
    """Open and dissect a capture file, PCAP or PCAPNG"""
    data = Raw.file(file)
    try:
        file_type = capture_file_type(data)
    finally:
        data.close()  # the file is opened again by the format, reading the magic number is enough
    if file_type is PCAPNGFile:
        return PCAPNGFile.open_file(file, mappings)
    return PCAPFile.open_file(file, mappings)


def capture_packets(file: CaptureFile) -> Iterator[Tuple[int, RawData]]:
    """Iterate the packets of a capture file as (link type, packet data) pairs"""
    if isinstance(file, PCAPNGFile):
        for block, link_type in PCAPNGPacketIterator(file):
            yield link_type, packet_data(block)
        return
    link_type = FileHeader.LinkType[PCAPFile.File_Header[file]]  # the same for all records
    for record in PCAPRecordIterator(file):
        yield link_type, PacketRecord.Packet_Data.as_raw(record) or Raw.empty


class CaptureStackLayer(StackLayer):
    """Stack layer for a capture file, PCAP or PCAPNG"""
    def __init__(self) -> None:
        super().__init__(PCAPFile)
        self.pcap = PCAPStackLayer()
        self.pcapng = PCAPNGStackLayer()

    def get_frame_type(self, state: StackState) -> Type[Frame]:
        return capture_file_type(state.data)

    def receive(self, state: StackState) -> Iterable[StackState]:
        if capture_file_type(state.data) is PCAPNGFile:
            return self.pcapng.receive(state)
        return self.pcap.receive(state)
