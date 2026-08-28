import pathlib

import pytest

from framing.frame_types.ethernet_frames import EthernetII, Ethernet_Payloads
from framing.frame_types.ipv4_frames import IPv4
from framing.frame_types.ipv6_frames import IPv6, IPReassembler
from framing.frame_types.udp_frames import UDP
from framing.frames import Frames
from framing.frame_types.pcap_frames import (
    PCAPFile, FileHeader, PacketRecord, PCAP_Payloads, PCAPStackLayer,
    frame_for_link_type, LINKTYPE_ETHERNET, LINKTYPE_RAW,
)
from framing.layer_stack import StackState
from framing.raw_data import Raw, RawData


def pcap_file_header(magic: str = "d4 c3 b2 a1", version: str = "02 00 04 00") -> RawData:
    """A PCAP file header with the given magic number and version, Ethernet link type"""
    return Raw.hex(f"{magic} {version} 00000000 00000000 ffff0000 01000000")


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

    records = PCAPFile.Packet_Records[pcap]
    assert len(records) == 2349
    b.close()


def test_pcap_decode_payload():
    b = Raw.file(pathlib.Path("samples/sample-1.pcap"))
    pcap = PCAPFile(Frames.dissect(b))

    c = 0
    off = PCAPFile.File_Header[pcap].bit_length() // 8
    for rec in PCAPFile.Packet_Records.iterate(pcap):
        c += 1
        off += rec.bit_length() // 8
    b.close()

    assert c == 2349
    assert off == 1607365


def test_pcap_layering():
    b = Raw.file(pathlib.Path("samples/sample-1-head.pcap"))
    pcap = PCAPFile(Frames.dissect(b))
    PCAP_Payloads.add_to(pcap)
    Ethernet_Payloads.add_to(pcap)

    print(f"{pcap}")

    rec = pcap.Packet_Records.item(pcap, 1)

    # backend gives frames implicitly
    eth_r = rec.backend.get(PacketRecord.Packet_Data)
    assert isinstance(eth_r, EthernetII)

    eth = PacketRecord.Packet_Data.as_frame(rec)
    assert isinstance(eth, EthernetII)
    assert eth.byte_length() == 66
    assert eth.bit_length() == 66 * 8
    assert EthernetII.data.as_frame(eth).bit_length() == 52 * 8
    assert EthernetII.padding[eth] == Raw.empty

    ip = EthernetII.data.as_frame(eth)
    assert isinstance(ip, IPv4)

    rec = pcap.Packet_Records.item(pcap, 2)
    eth = PacketRecord.Packet_Data.as_frame(rec)
    assert eth.bit_length() == 42 * 8
    assert (eth / EthernetII.data).bit_length() == 28 * 8
    assert EthernetII.padding[eth] == Raw.empty

    b.close()


def test_frame_for_link_type_ethernet():
    b = Raw.file(pathlib.Path("samples/sample-1.pcap"))
    pcap = PCAPFile(Frames.dissect(b))
    lt = FileHeader.LinkType[PCAPFile.File_Header[pcap]]
    assert lt == LINKTYPE_ETHERNET

    rec = pcap.Packet_Records.item(pcap, 1)
    top = frame_for_link_type(lt, PacketRecord.Packet_Data[rec])
    assert isinstance(top, EthernetII)
    assert isinstance(EthernetII.data.as_frame(top), IPv4)

    b.close()


def test_frame_for_link_type_raw_ip():
    b = Raw.file(pathlib.Path("samples/raw-ip.pcap"))
    pcap = PCAPFile(Frames.dissect(b))
    lt = FileHeader.LinkType[PCAPFile.File_Header[pcap]]
    assert lt == LINKTYPE_RAW

    recs = list(PCAPFile.Packet_Records.iterate(pcap))
    tops = [frame_for_link_type(lt, PacketRecord.Packet_Data[r]) for r in recs]
    assert isinstance(tops[0], IPv4)
    assert isinstance(tops[1], IPv6)

    reasm = IPReassembler()
    for top in tops:
        udp = reasm.push_frame(top)
        assert isinstance(udp, UDP)
        assert UDP.Destination_port[udp] == 0x1234

    b.close()


def test_check_format():
    # microsecond and nanosecond timestamp magic numbers, both least significant octet first
    for magic in ("d4 c3 b2 a1", "4d 3c b2 a1"):
        pcap = PCAPFile(Frames.dissect(pcap_file_header(magic)))
        assert pcap.check_format() is pcap

    # version 2.3 has the same packet record layout as 2.4
    for version in ("02 00 03 00", "02 00 04 00"):
        pcap = PCAPFile(Frames.dissect(pcap_file_header(version=version)))
        assert pcap.check_format() is pcap


def test_check_format_unsupported():
    # PCAPNG starts with a Section Header Block
    shb = Raw.hex("0a0d0d0a 1c000000 4d3c2b1a 01000000 ffffffffffffffff 1c000000")
    with pytest.raises(ValueError, match="PCAPNG format, which is not supported"):
        PCAPFile(Frames.dissect(shb)).check_format()

    # most significant octet first files, microsecond and nanosecond timestamps
    for magic in ("a1 b2 c3 d4", "a1 b2 3c 4d"):
        with pytest.raises(ValueError, match="most significant octet first"):
            PCAPFile(Frames.dissect(pcap_file_header(magic))).check_format()

    with pytest.raises(ValueError, match="Not a PCAP file, the magic number is 01020304"):
        PCAPFile(Frames.dissect(pcap_file_header("01 02 03 04"))).check_format()

    # a newer minor version may hold something we cannot read, likewise for other major versions
    for version in ("02 00 05 00", "03 00 04 00", "01 00 04 00", "1f 02 00 00"):
        with pytest.raises(ValueError, match="Unsupported PCAP file version .*versions up to 2.4"):
            PCAPFile(Frames.dissect(pcap_file_header(version=version))).check_format()

    # before version 2.3 the packet length fields are the other way around
    for version in ("02 00 00 00", "02 00 02 00"):
        with pytest.raises(ValueError, match="Length fields interchanged"):
            PCAPFile(Frames.dissect(pcap_file_header(version=version))).check_format()

    with pytest.raises(ValueError, match="too short to be a PCAP file"):
        PCAPFile(Frames.dissect(Raw.hex("d4 c3 b2 a1 02 00"))).check_format()


def test_open_file_checks_format():
    with pytest.raises(ValueError, match="PCAPNG format, which is not supported"):
        PCAPFile.open_file(pathlib.Path("samples/sample-1.pcapng"), mappings=None)

    # the supported files still open
    pcap = PCAPFile.open_file(pathlib.Path("samples/sample-1-head.pcap"), mappings=PCAP_Payloads)
    assert len(PCAPFile.Packet_Records[pcap]) == 10
    Frames.close(pcap)


def test_stack_layer_checks_format():
    data = Raw.file(pathlib.Path("samples/sample-1.pcapng"))
    try:
        with pytest.raises(ValueError, match="PCAPNG format, which is not supported"):
            list(PCAPStackLayer().receive(StackState(data)))
    finally:
        data.close()
