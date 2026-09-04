"""Capture files, PCAP and PCAPNG, told apart by the magic number of the file data"""

from typing import Iterable, Type, Union

from framing.base import Frame
from framing.frame_types.pcap_frames import (
    PCAPFile, PCAPStackLayer,
    MAGIC_NUMBER, MAGIC_NUMBER_MSB, MAGIC_NUMBER_MSB_NANOSECONDS, MAGIC_NUMBER_NANOSECONDS,
)
from framing.frame_types.pcapng_frames import (
    PCAPNGFile, PCAPNGStackLayer,
    MAGIC_NUMBER as MAGIC_NUMBER_PCAPNG,
)
from framing.layer_stack import StackLayer, StackState
from framing.raw_data import RawData


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
