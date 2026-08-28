import pathlib

import pytest

from framing.frame_types.ethernet_frames import EthernetII, Ethernet_Payloads
from framing.frame_types.ipv4_frames import IPv4
from framing.frame_types.ipv6_frames import IPv6, IPReassembler
from framing.frame_types.udp_frames import UDP
from framing.frames import Frames
from framing.frame_types.pcap_frames import (
    PCAPFile, FileHeader, PacketRecord, PCAP_Payloads, PCAPStackLayer,
    frame_for_link_type, is_msb_first, LINKTYPE_ETHERNET, LINKTYPE_RAW,
    MAGIC_NUMBER, MAGIC_NUMBER_MSB,
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
    # microsecond and nanosecond timestamp magic numbers, in both octet orders
    for magic in ("d4 c3 b2 a1", "4d 3c b2 a1", "a1 b2 c3 d4", "a1 b2 3c 4d"):
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

    with pytest.raises(ValueError, match="Not a PCAP file, the magic number is 01020304"):
        PCAPFile(Frames.dissect(pcap_file_header("01 02 03 04"))).check_format()

    # a newer minor version may hold something we cannot read, an older one has the packet length
    # fields interchanged, and other major versions are something else altogether
    for version in ("02 00 05 00", "02 00 02 00", "02 00 00 00", "03 00 04 00", "01 00 04 00", "1f 02 00 00"):
        with pytest.raises(ValueError, match="Unsupported PCAP file version .*versions 2.3 to 2.4"):
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


def to_msb_first(data: bytes) -> bytes:
    """Convert a least significant octet first PCAP file into a most significant octet first one"""
    header = bytearray(data[:24])
    for start, end in ((0, 4), (4, 6), (6, 8), (16, 20), (20, 24)):  # magic, version, snaplen, link type
        header[start:end] = data[start:end][::-1]
    out = bytearray(header)
    offset = 24
    while offset < len(data):
        captured = int.from_bytes(data[offset + 8:offset + 12], "little")
        for i in range(0, 16, 4):  # the four integers of a packet record header
            out += data[offset + i:offset + i + 4][::-1]
        out += data[offset + 16:offset + 16 + captured]
        offset += 16 + captured
    return bytes(out)


def test_is_msb_first():
    assert not is_msb_first(pcap_file_header("d4 c3 b2 a1"))
    assert not is_msb_first(pcap_file_header("4d 3c b2 a1"))
    assert is_msb_first(pcap_file_header("a1 b2 c3 d4"))
    assert is_msb_first(pcap_file_header("a1 b2 3c 4d"))
    assert not is_msb_first(Raw.hex("d4 c3"))  # too short to tell


def test_msb_first_file(tmp_path):
    lsb_file = pathlib.Path("samples/sample-1-head.pcap")
    msb_file = tmp_path / "msb-first.pcap"
    msb_file.write_bytes(to_msb_first(lsb_file.read_bytes()))

    lsb = PCAPFile.open_file(lsb_file, mappings=PCAP_Payloads + Ethernet_Payloads)
    msb = PCAPFile.open_file(msb_file, mappings=PCAP_Payloads + Ethernet_Payloads)

    lsb_header, msb_header = PCAPFile.File_Header[lsb], PCAPFile.File_Header[msb]
    assert FileHeader.Magic_Number[lsb_header] == MAGIC_NUMBER
    assert FileHeader.Magic_Number[msb_header] == MAGIC_NUMBER_MSB
    # the integers read the same in both octet orders
    for field in (FileHeader.Major_Version, FileHeader.Minor_Version, FileHeader.SnapLen, FileHeader.LinkType):
        assert field[msb_header] == field[lsb_header]
    assert FileHeader.LinkType[msb_header] == LINKTYPE_ETHERNET

    lsb_records, msb_records = PCAPFile.Packet_Records[lsb], PCAPFile.Packet_Records[msb]
    assert len(msb_records) == len(lsb_records) == 10
    for lsb_record, msb_record in zip(lsb_records, msb_records):
        for field in (PacketRecord.Timestamp, PacketRecord.Timestamp_2,
                      PacketRecord.Captured_Packet_length, PacketRecord.Original_Packet_length):
            assert field[msb_record] == field[lsb_record]
        assert PacketRecord.Packet_Data[msb_record] == PacketRecord.Packet_Data[lsb_record]

    # a field prints the octets as they are in the file
    assert FileHeader.SnapLen.to_string(msb_header) == "00 00 ff ff  ...."
    assert FileHeader.SnapLen.to_string(lsb_header) == "ff ff 00 00  ...."

    # the packets in the file are their own protocols, the octet order of the file does not reach them
    ip = msb_records[0] / PacketRecord.Packet_Data / EthernetII.data
    assert isinstance(ip, IPv4)
    assert IPv4.Total_Length[ip] == 0x34
    assert IPv4.Source_IP[ip] == Raw.hex("12 c2 0a 8e")

    Frames.close(lsb)
    Frames.close(msb)


def test_msb_first_compose():
    pcap = PCAPFile(Frames.compose(int_swap=True))
    hdr = PCAPFile.File_Header[pcap]
    FileHeader.Magic_Number[hdr] = MAGIC_NUMBER_MSB  # the magic number is raw data, not an integer
    FileHeader.SnapLen[hdr] = 0xffff
    FileHeader.LinkType[hdr] = LINKTYPE_ETHERNET

    encoded = pcap.encode()
    assert encoded == Raw.hex("a1b2c3d4 0002 0004 00000000 00000000 0000ffff 00000001")

    pcap = PCAPFile(Frames.dissect(encoded, int_swap=is_msb_first(encoded))).check_format()
    hdr = PCAPFile.File_Header[pcap]
    assert FileHeader.Major_Version[hdr] == 2
    assert FileHeader.Minor_Version[hdr] == 4
    assert FileHeader.SnapLen[hdr] == 0xffff
    assert FileHeader.LinkType[hdr] == LINKTYPE_ETHERNET
