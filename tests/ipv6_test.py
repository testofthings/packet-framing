import pathlib

from framing.frame_types.ethernet_frames import EthernetII, Ethernet_Payloads
from framing.frame_types.ipv6_frames import IPv6, IPv6_Payloads, ICMPv6, Fragment
from framing.frame_types.pcap_frames import PCAPFile, PacketRecord, PCAP_Payloads
from framing.frame_types.tcp_frames import TCP
from framing.frame_types.udp_frames import UDP
from framing.frames import Frames
from framing.raw_data import Raw


def test_decode_ip():
    pcap = PCAPFile.open_file(pathlib.Path("samples/ipv6-neighbor-solicitation.pcap"), mappings=PCAP_Payloads)

    raw_ip = EthernetII.data[PCAPFile.Packet_Records.item(pcap, 0) / PacketRecord.Packet_Data]
    ip = IPv6(Frames.dissect(raw_ip, mappings=IPv6_Payloads))

    assert IPv6.Version[ip] == 6
    assert IPv6.Traffic_class[ip] == 0
    assert str(IPv6.Source_address[ip].as_ip_address()) == "fe80::9400:1ff:fe98:e866"
    assert str(IPv6.Destination_address[ip].as_ip_address()) == "ff02::1:ff00:1"
    assert IPv6.Payload[ip].byte_length() == 32

    ic = IPv6.Payload.as_frame(ip)
    assert isinstance(ic, ICMPv6)

    Frames.close(pcap)


def test_decode_headers():
    pcap = PCAPFile.open_file(pathlib.Path("samples/ipv6-udp-frag.pcap"),
                              mappings=PCAP_Payloads + Ethernet_Payloads + IPv6_Payloads)

    fr = IPv6.Payload.as_frame(PCAPFile.Packet_Records.item(pcap, 0) / PacketRecord.Packet_Data / EthernetII.data)
    udp = Fragment.Payload.as_frame(fr)
    assert UDP.Length[udp] == 16392

    # NOTE: UDP is split into 12 fragments!


def test_decode_ip_tcp():
        pcap = PCAPFile.open_file(pathlib.Path("samples/tls13-over-ipv6.pcap"),
                                  mappings=PCAP_Payloads + Ethernet_Payloads + IPv6_Payloads)
        fr0 = PCAPFile.Packet_Records.item(pcap, 0) / PacketRecord.Packet_Data / EthernetII.data
        assert IPv6.Source_address[fr0] == Raw.hex("2a 00 1d 50 00 03 00 00 ac 3a 30 a5 20 41 35 44")
        assert IPv6.Destination_address[fr0] == Raw.hex("2a 04 fa 87 ff fe 00 00 00 00 00 00 c0 00 49 02")
        assert IPv6.Payload_length[fr0] == 40
        pl0 = IPv6.Payload.as_frame(fr0)
        assert TCP.Checksum[pl0] == Raw.hex("692a")
