import pathlib

from framing.base import *
from framing.frame_types.pcap_frames import PCAPFile, PCAP_Payloads, PacketRecord
from framing.frames import Frames
from framing.frame_types.ethernet_frames import EthernetII, Ethernet_Payloads


def test_ethernet():
    eth = EthernetII(Frames.compose())

    EthernetII.destination[eth] = Raw.hex("01 02 03 04 05 06")
    EthernetII.type[eth] = 1066
    EthernetII.data[eth] = Raw.hex("55 66 77 88")

    check = f"{eth}"

    assert EthernetII.destination.to_string(eth) == "01 02 03 04 05 06  ......"
    assert EthernetII.source.to_string(eth) == "00 00 00 00 00 00  ......"
    assert EthernetII.type.to_string(eth) == "04 2a  .*"
    assert EthernetII.data.to_string(eth) == "55 66 77 88  Ufw."
    assert EthernetII.padding.to_string(eth) == "()"

    assert EthernetII.destination.get_bit_length(eth) == 6 * 8
    assert EthernetII.source.get_bit_length(eth) == 6 * 8
    assert EthernetII.type.get_bit_length(eth) == 2 * 8
    # assert EthernetII.crc_checksum.get_bit_length(eth) == 4 * 8
    assert EthernetII.data.get_bit_length(eth) == 4 * 8
    assert EthernetII.padding.get_bit_length(eth) == 0 * 8

    assert eth.get_byte_length() == 18

    raw = eth.backend.encode()
    assert EthernetII.padding.get_bit_length(eth) == 46 * 8
    assert raw.byte_length() == 64

    assert eth.get_byte_length() == 64


def test_decode_eth_and_ip():
    b = Raw.file(pathlib.Path("samples/sample-2.pcap"))
    pcap = PCAPFile(Frames.dissect(b))
    PCAP_Payloads.add_to(pcap)
    Ethernet_Payloads.add_to(pcap)

    rec = PCAPFile.Packet_Records.get_item(pcap, 0)
    eth = PacketRecord.Packet_Data.as_frame(rec)
    ip = EthernetII.data.as_frame(eth)
    assert ip.get_bit_length() == 0x34 * 8

    pad = EthernetII.padding[eth]
    assert EthernetII.padding[eth] == Raw.empty
    assert eth.get_bit_length() == 528
