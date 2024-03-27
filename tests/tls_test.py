import pathlib
from framing.frame_processors import IP2TCP, Ethernet2IP, PCAP2Ethernet, ProcessorIterator
from framing.frame_types.ethernet_frames import Ethernet_Payloads
from framing.frame_types.ip_utilities import IP2TCPStream, TCPDataTable, TCPReassembler
from framing.frame_types.ipv6_frames import IPv6_Payloads
from framing.frame_types.pcap_frames import PCAP_Payloads, PCAPFile, PCAPRecordIterator
from framing.frame_types.tls_frames import TLSHandshake, TLSRecord, TLSRecord_Payloads
from framing.frames import Frames


def test_tls_record():
    pcap = PCAPFile.open_file(pathlib.Path("samples/tls13-over-ipv6.pcap"),
                              mappings=PCAP_Payloads + Ethernet_Payloads + IPv6_Payloads)

    pro = PCAP2Ethernet(Ethernet2IP(IP2TCP()))
    asm = TCPReassembler(full_streams=True)
    recs = {}
    for pcap_r in PCAPRecordIterator(pcap):
        tcp_ip = pro.push(pcap_r)
        k, queue = asm.push_queue(tcp_ip)
        if not queue:
            continue
        rec = Frames.dissect_pull(TLSRecord, queue)
        while rec:
            recs.setdefault(k, []).append(rec)
            rec = Frames.dissect_pull(TLSRecord, queue)

    client, server = recs.values()
    assert len(client) == 7
    assert len(server) == 10

    hs = TLSRecord_Payloads.decode_payload(client[0], TLSRecord.fragment)
    assert isinstance(hs, TLSHandshake)


