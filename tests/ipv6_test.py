import pathlib

from framing.frame_types.ethernet_frames import EthernetII
from framing.frame_types.ipv6_frames import IPv6
from framing.frame_types.pcap_frames import PCAPFile, PacketRecord, PCAP_Payloads
from framing.frames import Frames


def test_decode_ip():
    pcap = PCAPFile.open_file(pathlib.Path("samples/ipv6-neighbor-solicitation.pcap"), mappings=PCAP_Payloads)

    raw_ip = EthernetII.data[PCAPFile.Packet_Records.item(pcap, 0) / PacketRecord.Packet_Data]
    ip = IPv6(Frames.dissect(raw_ip))

    assert IPv6.Version[ip] == 6
    assert str(IPv6.Source_address[ip].as_ip_address()) == "fe80::9400:1ff:fe98:e866"
    assert str(IPv6.Destination_address[ip].as_ip_address()) == "ff02::1:ff00:1"

    Frames.close(pcap)
