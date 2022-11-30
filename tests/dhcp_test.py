import pathlib

from framing.frame_types.dhcp_frames import DHCP
from framing.frame_types.dns_frames import DNSMessage
from framing.frame_types.ethernet_frames import Ethernet_Payloads, EthernetII
from framing.frame_types.ipv4_frames import IPv4, IP_Payloads
from framing.frame_types.pcap_frames import PCAPFile, PCAP_Payloads, PacketRecord
from framing.frame_types.udp_frames import UDP
from framing.frames import Frames
from framing.raw_data import Raw


def test_decode_dns():
    pcap = PCAPFile.open_file(pathlib.Path("samples/sample-1.pcap"),
                              mappings=PCAP_Payloads + Ethernet_Payloads + IP_Payloads)

    # Frame 208

    raw = UDP.Data[PCAPFile.Packet_Records.item(pcap, 207) / PacketRecord.Packet_Data / EthernetII.data / IPv4.Payload]
    msg = DHCP(Frames.dissect(raw))
    assert DHCP.xid[msg] == 0x71b7bbc1
