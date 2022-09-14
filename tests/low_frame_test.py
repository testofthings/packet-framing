from framing.base import *
from framing.frames import Frames, BaseFrame
from framing.low_frames import EthernetII
from framing.pcap_frames import PCAP


def test_ethernet():
    eth = BaseFrame(EthernetII)

    eth.set(EthernetII.destination, Raw.hex("01 02 03 04 05 06"))
    eth.set(EthernetII.type, 1066)
    eth.set(EthernetII.data, Raw.hex("55 66 77 88"))

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

    assert Frames.get_byte_length(eth) == 22

    raw = eth.backend.encode()
    assert EthernetII.padding.get_bit_length(eth) == 42 * 8
    assert raw.byte_length() == 64

    assert Frames.get_byte_length(eth) == 64

    # FIXME: Below shows that types not enforced (they would when all definitions are in the same source file!)

    pcap = BaseFrame(PCAP)
    pcap.set(EthernetII.type, 55)
    jee = pcap.get(EthernetII.type)
    pcap.set(EthernetII.type, "as")
    jee2 = eth.get(EthernetII.type)
    eth.set(EthernetII.type, "as")
