import pathlib
from framing.data_queue import RawDataQueue
from framing.frame_processors import IP2TCP, Ethernet2IP, PCAP2Ethernet, ProcessorIterator
from framing.frame_types.ethernet_frames import Ethernet_Payloads
from framing.frame_types.ip_utilities import IP2TCPStream, TCPDataTable, TCPReassembler
from framing.frame_types.ipv6_frames import IPv6_Payloads
from framing.frame_types.pcap_frames import PCAP_Payloads, PCAPFile, PCAPRecordIterator
from framing.frame_types.tls_frames import TLSApplicationData, TLSChangeCipherSpec, TLSHandshake, TLSRecord, TLSRecord_Payloads
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

    client_recs, server_recs = recs.values()
    assert len(client_recs) == 7
    assert len(server_recs) == 10

    messages = {}
    for k, rec_list in recs.items():
        record_data = {}
        for rec in rec_list:
            mgs_type = TLSRecord_Payloads.resolve_payload_type(rec, TLSRecord.fragment)
            queue = record_data.setdefault(mgs_type, RawDataQueue())
            queue.push(TLSRecord.fragment[rec])
            msg = Frames.dissect_pull(mgs_type, queue)
            if msg:
                messages.setdefault(k, []).append(msg)

    client_msgs, server_msgs = messages.values()
    assert len(client_msgs) == 7
    assert len(server_msgs) == 10

    client_msg_types = [type(m) for m in client_msgs]
    server_msg_types = [type(m) for m in server_msgs]
    assert client_msg_types[:3] == [TLSHandshake, TLSChangeCipherSpec, TLSApplicationData]
    assert all([t == TLSApplicationData for t in client_msg_types[3:]])
    assert server_msg_types[:3] == [TLSHandshake, TLSChangeCipherSpec, TLSApplicationData]
    assert all([t == TLSApplicationData for t in server_msg_types[3:]])

