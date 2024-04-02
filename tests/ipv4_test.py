import ipaddress
import pathlib

from framing.backends import BackendImplementation
from framing.frame_processors import PCAP2Ethernet, Ethernet2IP, IP2UDP
from framing.frame_types.ethernet_frames import EthernetII, Ethernet_Payloads
from framing.frame_types.ipv4_frames import IPv4, IP_Payloads
from framing.frame_types.ipv6_frames import IPReassembler, IPStackLayer
from framing.frame_types.pcap_frames import PCAPFile, PCAP_Payloads, PacketRecord, PCAPRecordIterator
from framing.frame_types.tcp_frames import TCP
from framing.frame_types.udp_frames import UDP
from framing.frames import Frames
from framing.raw_data import Raw


def test_ipv4():
    ip = IPv4(Frames.compose())
    ip_s = f"{ip}"

    ip.encode()
    assert IPv4.Version[ip] == 4
    assert IPv4.IHL[ip] == 5
    assert IPv4.Total_Length[ip] == 20
    assert IPv4.Options[ip] == Raw.empty
    assert IPv4.Payload[ip] == Raw.empty

    # NOTE: Missing option structures and padding logic
    IPv4.Options[ip] = Raw.hex("01020304")
    ip.encode()
    assert IPv4.Version[ip] == 4
    assert IPv4.IHL[ip] == 6
    assert IPv4.Total_Length[ip] == 24
    assert IPv4.Options[ip] == Raw.hex("01020304")
    assert IPv4.Payload[ip] == Raw.empty


def test_decode_ip():
    pcap = PCAPFile.open_file(pathlib.Path("samples/sample-1-head.pcap"), mappings=PCAP_Payloads)

    raw_ip = EthernetII.data[PCAPFile.Packet_Records.item(pcap, 0) / PacketRecord.Packet_Data]
    ip = IPv4(Frames.dissect(raw_ip))

    assert IPv4.Version[ip] == 4
    assert IPv4.IHL[ip] == 5
    assert IPv4.Source_IP[ip].as_ip_address() == ipaddress.ip_address("18.194.10.142")
    assert IPv4.Destination_IP[ip].as_ip_address() == ipaddress.ip_address("192.168.4.16")
    assert IPv4.Total_Length[ip] == 0x34
    assert IPv4.Options[ip] == Raw.empty
    assert ip.bit_length() == 0x34 * 8

    # check which fields gets decoded
    ip = IPv4(Frames.dissect(raw_ip))
    assert BackendImplementation.list_resolved_fields(ip) == []
    a = ip.bit_length()
    # FIXME: No need to resolve IHL!
    assert BackendImplementation.list_resolved_fields(ip) == [IPv4.Total_Length]
    a = IPv4.Payload[ip]
    assert BackendImplementation.list_resolved_fields(ip) == [IPv4.IHL, IPv4.Payload, IPv4.Total_Length]

    Frames.close(pcap)


def test_decode_payload():
    pcap = PCAPFile.open_file(pathlib.Path("samples/sample-1-head.pcap"),
                              mappings=PCAP_Payloads + Ethernet_Payloads + IP_Payloads)

    ip = PCAPFile.Packet_Records.item(pcap, 0) / PacketRecord.Packet_Data / EthernetII.data
    pl = IPv4.Payload.as_frame(ip)
    assert isinstance(ip, IPv4)
    assert isinstance(pl, TCP)

    Frames.close(pcap)


def test_decode_fragments():
    pcap = PCAPFile.open_file(pathlib.Path("samples/ipv4-udp-frag.pcap"),
                              mappings=PCAP_Payloads + Ethernet_Payloads + IP_Payloads)

    pro = PCAP2Ethernet(Ethernet2IP())
    de_frag = IPStackLayer()
    data = None
    for pcap_r in PCAPRecordIterator(pcap):
        ip = pro.push(pcap_r)
        if ip:
            data = de_frag.push_frame(ip)
            if data:
                break
    assert isinstance(data, UDP)
    assert data.byte_length() == 16392
    assert UDP.Source_port[data] == 34910
    assert UDP.Destination_port[data] == 6666
    assert UDP.Length[data] == 16392
    assert UDP.Data[data].byte_length() == 16384

    pro = PCAP2Ethernet(Ethernet2IP(IP2UDP()))
    data = None
    for pcap_r in PCAPRecordIterator(pcap):
        udp_ip = pro.push(pcap_r)
        if udp_ip:
            break
    data, ip = udp_ip
    assert UDP.Data[data].byte_length() == 16384

