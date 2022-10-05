import pathlib

from framing.frame_types.ethernet_frames import EthernetII, Ethernet_Payloads
from framing.frame_types.ipv4_frames import IPv4
from framing.frames import Frames
from framing.frame_types.pcap_frames import PCAPFile, FileHeader, PacketRecord, PCAP_Payloads
from framing.raw_data import Raw


def test_pcap():
    pcap = PCAPFile(Frames.compose())
    pcap_hdr = PCAPFile.File_Header[pcap]
    assert FileHeader.Magic_Number[pcap_hdr] == Raw.hex("D4C3B2A1")
    assert FileHeader.Major_Version[pcap_hdr] == 2
    assert FileHeader.Minor_Version[pcap_hdr] == 4

    records = PCAPFile.Packet_Records.set_repeat(pcap, 3)
    assert len(records) == 3

    as_s = Frames.dump(pcap, width=80)

    PacketRecord.Packet_Data[records[0]] = Raw.string("This")
    PacketRecord.Packet_Data[records[1]] = Raw.string("is")
    PacketRecord.Packet_Data[records[2]] = Raw.string("fun")

    enc = pcap.encode()

    assert PacketRecord.Captured_Packet_length[records[0]] == 4
    assert PacketRecord.Captured_Packet_length[records[1]] == 2
    assert PacketRecord.Captured_Packet_length[records[2]] == 3

    assert PacketRecord.Original_Packet_length[records[2]] == 3


def test_pcap_decode():
    b = Raw.file(pathlib.Path("samples/sample-1.pcap"))
    pcap = PCAPFile(Frames.dissect(b))
    pcap_hdr = PCAPFile.File_Header[pcap]
    assert FileHeader.Magic_Number[pcap_hdr] == Raw.hex("D4C3B2A1")
    assert FileHeader.Major_Version[pcap_hdr] == 2
    assert FileHeader.Minor_Version[pcap_hdr] == 4
    assert FileHeader.SnapLen[pcap_hdr] == 0xffff

    records = PCAPFile.Packet_Records[pcap_hdr]
    assert len(records) == 2349
    b.close()


def test_pcap_decode_payload():
    b = Raw.file(pathlib.Path("samples/sample-1.pcap"))
    pcap = PCAPFile(Frames.dissect(b))

    c = 0
    off = PCAPFile.File_Header[pcap].get_byte_length()
    for rec in PCAPFile.Packet_Records.iterate(pcap):
        c += 1
        off += rec.get_byte_length()
    b.close()

    assert c == 2349
    assert off == 1607365


def test_pcap_layering():
    b = Raw.file(pathlib.Path("samples/sample-1-head.pcap"))
    pcap = PCAPFile(Frames.dissect(b))
    PCAP_Payloads.add_to(pcap)
    Ethernet_Payloads.add_to(pcap)

    rec = pcap.Packet_Records.item(pcap, 1)
    eth = PacketRecord.Packet_Data.as_frame(rec)
    assert isinstance(eth, EthernetII)
    assert eth.get_byte_length() == 66
    assert eth.get_bit_length() == 66 * 8
    assert EthernetII.data.as_frame(eth).get_byte_length() == 52
    assert EthernetII.padding[eth] == Raw.empty

    ip = EthernetII.data.as_frame(eth)
    assert isinstance(ip, IPv4)

    rec = pcap.Packet_Records.item(pcap, 2)
    eth = PacketRecord.Packet_Data.as_frame(rec)
    assert eth.get_bit_length() == 42 * 8
    assert (eth / EthernetII.data).get_byte_length() == 28
    assert EthernetII.padding[eth] == Raw.empty

    b.close()
