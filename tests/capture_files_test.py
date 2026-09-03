import pathlib
from typing import Iterator, Optional, Tuple

import pytest

from framing.base import LayerMapping
from framing.command import StackBuilder
from framing.frame_types.capture_files import (
    CaptureFile, CaptureStackLayer, capture_file_type,
)
from framing.frame_types.pcap_frames import LINKTYPE_ETHERNET, FileHeader, PCAPFile, PCAPRecordIterator, PacketRecord
from framing.frame_types.pcapng_frames import PCAPNGFile, PCAPNGPacketIterator, packet_data
from framing.frames import Frames
from framing.layer_stack import StackState
from framing.raw_data import Raw, RawData


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


def test_capture_file_type():
    # microsecond and nanosecond timestamps, in both octet orders
    for magic in ("d4 c3 b2 a1", "4d 3c b2 a1", "a1 b2 c3 d4", "a1 b2 3c 4d"):
        assert capture_file_type(Raw.hex(magic)) is PCAPFile
    # the PCAPNG Section Header Block type reads the same in both octet orders
    assert capture_file_type(Raw.hex("0a 0d 0d 0a")) is PCAPNGFile

    with pytest.raises(ValueError, match="Not a PCAP or PCAPNG file, the magic number is 01020304"):
        capture_file_type(Raw.hex("01 02 03 04"))


def test_open_capture_file():
    pcap = open_capture_file(pathlib.Path("samples/sample-1-head.pcap"))
    assert isinstance(pcap, PCAPFile)
    Frames.close(pcap)

    pcapng = open_capture_file(pathlib.Path("samples/tls13-over-ipv6.pcapng"))
    assert isinstance(pcapng, PCAPNGFile)
    Frames.close(pcapng)

    # the format is told by the data, not by the name of the file
    with pytest.raises(ValueError, match="Not a PCAP or PCAPNG file"):
        open_capture_file(pathlib.Path("samples/hello-world.txt"))


def test_capture_packets_are_the_same_in_both_formats():
    # samples/sample-1.pcapng holds the same traffic as samples/sample-1.pcap
    pcap = open_capture_file(pathlib.Path("samples/sample-1.pcap"))
    pcapng = open_capture_file(pathlib.Path("samples/sample-1.pcapng"))

    pcap_packets = list(capture_packets(pcap))
    pcapng_packets = list(capture_packets(pcapng))
    assert len(pcap_packets) == len(pcapng_packets) == 2349

    for (pcap_link_type, pcap_data), (pcapng_link_type, pcapng_data) in zip(pcap_packets, pcapng_packets):
        assert pcap_link_type == pcapng_link_type == LINKTYPE_ETHERNET
        assert pcap_data == pcapng_data

    Frames.close(pcap)
    Frames.close(pcapng)


def test_capture_stack_layer():
    layer = CaptureStackLayer()
    for file, expected in (("samples/sample-1-head.pcap", PCAPFile),
                           ("samples/tls13-over-ipv6.pcapng", PCAPNGFile)):
        data = Raw.file(pathlib.Path(file))
        try:
            assert layer.get_frame_type(StackState(data)) is expected
        finally:
            data.close()


def test_capture_stack():
    # the command-line stack reads both formats, the frames inside are the same
    for file, expected in (
            ("samples/sample-1-head.pcap", {"PCAPFile / PacketRecord / 1=EthernetII": 2,
                                            "PCAPFile / PacketRecord / 1=EthernetII / 2048=IPv4": 8}),
            ("samples/tls13-over-ipv6.pcapng", {"PCAPNGFile / Block / 1=EthernetII / 34525=IPv6": 23})):
        stack = StackBuilder.build_stack({"udp": {}})
        data = Raw.file(pathlib.Path(file))
        try:
            layers: dict = {}
            for state in stack.receive(StackState(data)):
                name = state.get_layer_names()
                layers[name] = layers.get(name, 0) + 1
        finally:
            data.close()
        assert layers == expected
