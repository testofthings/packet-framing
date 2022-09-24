from framing.base import *
from framing.frames import Frames
from framing.low_frames import EthernetII


def test_ethernet():
    eth = EthernetII(Frames.compose())

    EthernetII.destination[eth] = Raw.hex("01 02 03 04 05 06")
    EthernetII.type[eth] = 1066
    EthernetII.data[eth] = Raw.hex("55 66 77 88")

    check = f"{eth}"

    assert EthernetII.destination.to_string(eth) == "01 02 03 04 05 06"
    assert EthernetII.source.to_string(eth) == "00 00 00 00 00 00"
    assert EthernetII.type.to_string(eth) == "04 2a"
    assert EthernetII.data.to_string(eth) == "55 66 77 88"
    assert EthernetII.padding.to_string(eth) == "()"

    assert EthernetII.destination.get_bit_length(eth) == 6 * 8
    assert EthernetII.source.get_bit_length(eth) == 6 * 8
    assert EthernetII.type.get_bit_length(eth) == 2 * 8
    assert EthernetII.crc_checksum.get_bit_length(eth) == 4 * 8
    assert EthernetII.data.get_bit_length(eth) == 4 * 8
    assert EthernetII.padding.get_bit_length(eth) == 0 * 8

    assert eth.get_byte_length() == 22

    raw = eth.backend.encode()
    assert EthernetII.padding.get_bit_length(eth) == 42 * 8
    assert raw.byte_length() == 64

    assert eth.get_byte_length() == 64
