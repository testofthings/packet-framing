import ipaddress
import pathlib

from framing.frame_processors import IP2TCP, PCAP2Ethernet, Ethernet2IP
from framing.frame_types.ethernet_frames import Ethernet_Payloads, EthernetII
from framing.frame_types.ipv4_frames import IPv4, IP_Payloads
from framing.frame_types.pcap_frames import PCAPFile, PCAP_Payloads, PacketRecord, PCAPRecordIterator
from framing.frame_types.tcp_frames import TCP, TCPFlag, TCPDataQueue
from framing.frames import Frames
from framing.raw_data import Raw


def test_decode_tcp():
    pcap = PCAPFile.open_file(pathlib.Path("samples/sample-1-head.pcap"), mappings=PCAP_Payloads + Ethernet_Payloads)

    raw = IPv4.Payload[PCAPFile.Packet_Records.item(pcap, 0) / PacketRecord.Packet_Data / EthernetII.data]
    tcp = TCP(Frames.dissect(raw))
    assert TCP.Checksum[tcp] == Raw.octets(0x84, 0x25)
    assert TCP.Data[tcp] == Raw.empty
    assert TCP.Flags[tcp] & TCPFlag.FIN == 0
    assert TCP.Flags[tcp] & TCPFlag.ACK != 0

    raw = IPv4.Payload[PCAPFile.Packet_Records.item(pcap, 6) / PacketRecord.Packet_Data / EthernetII.data]
    tcp = TCP(Frames.dissect(raw))
    assert TCP.Checksum[tcp] == Raw.octets(0x7d, 0x12)
    assert TCP.Source_port[tcp] == 64973
    assert TCP.Destination_port[tcp] == 443
    assert TCP.Options[tcp].byte_length() == 12
    assert TCP.Data[tcp].byte_length() == 24


def test_decode_tcp_payload():
    pcap = PCAPFile.open_file(pathlib.Path("samples/sample-1.pcap"),
                              mappings=PCAP_Payloads + Ethernet_Payloads + IP_Payloads)

    conns = {}

    tcp_pro = PCAP2Ethernet(Ethernet2IP(IP2TCP()))

    f_number = 0
    for pcap_r in PCAPRecordIterator(pcap):
        f_number += 1
        tcp_ip = tcp_pro.push(pcap_r)
        if not tcp_ip:
            continue
        tcp, ip = tcp_ip
        k = ip.get_addresses(), tcp.get_ports()
        c = conns.get(k)
        if c is None:
            if TCP.Flags[tcp] & TCPFlag.SYN:
                c = TCPDataQueue(tcp)
                conns[k] = c
        elif not c.is_closed():
            c.push_frame(tcp)

    for q in conns.values():
        q.close()

    assert len(conns) == 26

    q = conns[((ipaddress.ip_address("192.168.4.16"), ipaddress.ip_address("17.253.39.208")), (64982, 443))]
    assert q.head.byte_length() == 1695

    q = conns[((ipaddress.ip_address("17.253.39.208"), ipaddress.ip_address("192.168.4.16")), (443, 64982))]
    assert q.head.byte_length() == 6723

