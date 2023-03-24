import pathlib

import pytest

from framing.frame_processors import PCAP2Ethernet, Ethernet2IP, IP2TCP
from framing.frame_types.dns_frames import DNSMessage, DNSHeader, DNSQuestion, DNSName, DNSResource, \
    SOA_RDATA, RDATA, DNSMessageTCP
from framing.frame_types.ethernet_frames import Ethernet_Payloads, EthernetII
from framing.frame_types.ip_utilities import TCPReassembler
from framing.frame_types.ipv4_frames import IPv4, IP_Payloads
from framing.frame_types.pcap_frames import PCAPFile, PCAP_Payloads, PacketRecord, PCAPRecordIterator
from framing.frame_types.udp_frames import UDP
from framing.frames import Frames
from framing.raw_data import Raw


def test_decode_dns():
    pcap = PCAPFile.open_file(pathlib.Path("samples/sample-1.pcap"),
                              mappings=PCAP_Payloads + Ethernet_Payloads + IP_Payloads)

    # Frame 136

    raw = UDP.Data[PCAPFile.Packet_Records.item(pcap, 135) / PacketRecord.Packet_Data / EthernetII.data / IPv4.Payload]
    msg = DNSMessage(Frames.dissect(raw))

    qds = DNSMessage.Question[msg]
    ans = DNSMessage.Answer[msg]
    nss = DNSMessage.Authority[msg]
    ads = DNSMessage.Additional[msg]
    assert len(qds) == 1
    assert len(ans) == 0
    assert len(nss) == 1
    assert len(ads) == 0

    print(f"{msg}")

    a_name = DNSName.string(qds[0], DNSQuestion.QNAME)
    assert a_name == "mask.apple-dns.net"
    a_name = DNSName.string(nss[0], DNSResource.NAME)
    assert a_name == "mask.apple-dns.net"

    assert DNSResource.TYPE[nss[0]] == 0x0006
    assert DNSResource.CLASS[nss[0]] == 0x0001
    assert DNSResource.TTL[nss[0]] == 0x110

    # NOTE: Ugly!
    rdata = DNSResource.RDATA.as_frame(nss[0])
    soa = RDATA.SOA[rdata]
    assert SOA_RDATA.EXPIRE[soa] == 0x127500


    # Frame 135

    raw = UDP.Data[PCAPFile.Packet_Records.item(pcap, 134) / PacketRecord.Packet_Data / EthernetII.data / IPv4.Payload]
    msg = DNSMessage(Frames.dissect(raw))
    hdr = DNSMessage.Header[msg]

    assert DNSHeader.ID[hdr] == Raw.octets(0x59, 0x80)
    assert DNSHeader.QDCOUNT[hdr] == 1

    qds = DNSMessage.Question[msg]
    assert len(qds) == 1
    qd = qds[0]

    q_name = DNSQuestion.QNAME[qd]
    assert q_name == [Raw.string("\x04mask"), Raw.string("\x09apple-dns"), Raw.string("\x03net"), Raw.string("\x00")]
    assert DNSQuestion.QTYPE[qd] == 0x0041
    assert DNSQuestion.QCLASS[qd] == 0x0001


def test_decode_complex_dns():
    pcap = PCAPFile.open_file(pathlib.Path("samples/complex-dns.pcap"),
                              mappings=PCAP_Payloads + Ethernet_Payloads + IP_Payloads)

    raw = UDP.Data[PCAPFile.Packet_Records.item(pcap, 0) / PacketRecord.Packet_Data / EthernetII.data / IPv4.Payload]
    msg = DNSMessage(Frames.dissect(raw))

    names = []
    for rd in DNSMessage.Additional.iterate(msg):
        name = DNSName.string(rd, DNSResource.NAME)
        names.append(name)
    for rd in DNSMessage.Question.iterate(msg):
        name = DNSName.string(rd, DNSQuestion.QNAME)
        names.append(name)
    for rd in DNSMessage.Answer.iterate(msg):
        name = DNSName.string(rd, DNSResource.NAME)
        names.append(name)
    for rd in DNSMessage.Authority.iterate(msg):
        name = DNSName.string(rd, DNSResource.NAME)
        names.append(name)
    for rd in DNSMessage.Answer.iterate(msg):
        name = DNSName.string(rd, DNSResource.NAME)
        names.append(name)

    ns = sorted(set(names))
    assert ns == ['awsota.linkplay.com', 'd1enchupjctwud.cloudfront.net', 'ns-317.awsdns-39.com']


def test_malformed_dns():
    pcap = PCAPFile.open_file(pathlib.Path("samples/malformed-dns.pcap"),
                              mappings=PCAP_Payloads + Ethernet_Payloads + IP_Payloads)

    raw = UDP.Data[PCAPFile.Packet_Records.item(pcap, 0) / PacketRecord.Packet_Data / EthernetII.data / IPv4.Payload]
    msg0 = DNSMessage(Frames.dissect(raw))
    assert msg0.byte_length() == 90

    for rd in DNSMessage.Question.iterate(msg0):
        name = DNSName.string(rd, DNSQuestion.QNAME)
        print(f"name={name}")

    raw = UDP.Data[PCAPFile.Packet_Records.item(pcap, 1) / PacketRecord.Packet_Data / EthernetII.data / IPv4.Payload]
    msg1 = DNSMessage(Frames.dissect(raw))

    with pytest.raises(EOFError):
        assert msg1.byte_length() == 90

    # failure when trying to get Qnames
    with pytest.raises(ValueError):
        for rd in DNSMessage.Question.iterate(msg1):
            name = DNSName.string(rd, DNSQuestion.QNAME)
            print(f"name={name}")


def test_dns_tcp():
    # sample capture from: https://packetlife.net/
    pcap = PCAPFile.open_file(pathlib.Path("samples/dns-zone-transfer-axfr.cap"),
                              mappings=PCAP_Payloads + Ethernet_Payloads + IP_Payloads)

    pro = PCAP2Ethernet(Ethernet2IP(IP2TCP()))
    asm = TCPReassembler(full_streams=True)
    dns = []
    for pcap_r in PCAPRecordIterator(pcap):
        tcp_ip = pro.push(pcap_r)
        if not tcp_ip:
            continue
        raw = asm.push(tcp_ip)
        if raw:
            dns.append(DNSMessageTCP(Frames.dissect(raw)))

    assert len(dns) == 2
    assert DNSMessageTCP.Length[dns[0]] == 28
    assert DNSMessageTCP.Length[dns[1]] == 195
