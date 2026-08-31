import pathlib

import pytest

from framing.frame_types.ethernet_frames import EthernetII, Ethernet_Payloads
from framing.frame_types.ipv4_frames import IPv4
from framing.frame_types.pcap_frames import LINKTYPE_ETHERNET, LINKTYPE_RAW
from framing.frame_types.pcapng_frames import (
    BLOCK_ENHANCED_PACKET, BLOCK_INTERFACE_DESCRIPTION, BLOCK_SECTION_HEADER, BLOCK_SIMPLE_PACKET,
    BYTE_ORDER_MAGIC, BYTE_ORDER_MAGIC_MSB, Block, BlockBody, EnhancedPacketBlock,
    InterfaceDescriptionBlock, PCAPNGFile, PCAPNGPacketIterator, SectionHeaderBlock,
    SimplePacketBlock, is_msb_first, packet_data,
)
from framing.frames import Frames
from framing.raw_data import Raw


def block(block_type: int, body: bytes, lsb_first: bool = True) -> bytes:
    """A block with the given type and body, the total length filled in"""
    order = "little" if lsb_first else "big"
    total = len(body) + 12
    return block_type.to_bytes(4, order) + total.to_bytes(4, order) + body + total.to_bytes(4, order)


def section_header(lsb_first: bool = True) -> bytes:
    order = "little" if lsb_first else "big"
    magic = BYTE_ORDER_MAGIC if lsb_first else BYTE_ORDER_MAGIC_MSB
    body = magic.as_bytes(0, 4) + (1).to_bytes(2, order) + (0).to_bytes(2, order) + b"\xff" * 8
    return block(BLOCK_SECTION_HEADER, body, lsb_first)


def interface_description(link_type: int = LINKTYPE_ETHERNET, lsb_first: bool = True) -> bytes:
    order = "little" if lsb_first else "big"
    body = link_type.to_bytes(2, order) + b"\x00\x00" + (0xffff).to_bytes(4, order)
    return block(BLOCK_INTERFACE_DESCRIPTION, body, lsb_first)


def enhanced_packet(data: bytes, interface_id: int = 0, lsb_first: bool = True) -> bytes:
    order = "little" if lsb_first else "big"
    body = (interface_id.to_bytes(4, order) + (0x11223344).to_bytes(4, order)
            + (0x55667788).to_bytes(4, order) + len(data).to_bytes(4, order)
            + len(data).to_bytes(4, order) + data + b"\x00" * (-len(data) % 4))
    return block(BLOCK_ENHANCED_PACKET, body, lsb_first)


def simple_packet(data: bytes, lsb_first: bool = True) -> bytes:
    order = "little" if lsb_first else "big"
    body = len(data).to_bytes(4, order) + data + b"\x00" * (-len(data) % 4)
    return block(BLOCK_SIMPLE_PACKET, body, lsb_first)


def open_data(data: bytes) -> PCAPNGFile:
    """Dissect PCAPNG data, the octet order told by the Byte-Order Magic"""
    raw = Raw.bytes(data)
    return PCAPNGFile(Frames.dissect(raw, int_swap=is_msb_first(raw))).check_format()


def test_pcapng_blocks():
    data = section_header() + interface_description() + enhanced_packet(b"\xaa\xbb\xcc")
    f = open_data(data)

    blocks = PCAPNGFile.Blocks[f]
    assert len(blocks) == 3
    assert [Block.Block_Type[b] for b in blocks] == [BLOCK_SECTION_HEADER,
                                                     BLOCK_INTERFACE_DESCRIPTION,
                                                     BLOCK_ENHANCED_PACKET]
    # every block tells its length twice
    for b in blocks:
        assert Block.Block_Total_Length[b] == Block.Block_Total_Length_2[b] == b.byte_length()

    header = Block.Body.get_choice(blocks[0])
    assert isinstance(header, SectionHeaderBlock)
    assert SectionHeaderBlock.Byte_Order_Magic[header] == BYTE_ORDER_MAGIC
    assert SectionHeaderBlock.Major_Version[header] == 1
    assert SectionHeaderBlock.Minor_Version[header] == 0
    assert SectionHeaderBlock.Section_Length[header] == 0xffffffffffffffff  # not specified

    interface = Block.Body.get_choice(blocks[1])
    assert isinstance(interface, InterfaceDescriptionBlock)
    assert InterfaceDescriptionBlock.LinkType[interface] == LINKTYPE_ETHERNET
    assert InterfaceDescriptionBlock.SnapLen[interface] == 0xffff

    packet = Block.Body.get_choice(blocks[2])
    assert isinstance(packet, EnhancedPacketBlock)
    assert EnhancedPacketBlock.Interface_ID[packet] == 0
    assert EnhancedPacketBlock.Timestamp_High[packet] == 0x11223344
    assert EnhancedPacketBlock.Timestamp_Low[packet] == 0x55667788
    assert EnhancedPacketBlock.Captured_Packet_Length[packet] == 3
    assert EnhancedPacketBlock.Original_Packet_Length[packet] == 3
    assert EnhancedPacketBlock.Packet_Data[packet] == Raw.hex("aa bb cc")
    assert EnhancedPacketBlock.Options[packet] == Raw.hex("00")  # the padding of the packet data

    assert f.byte_length() == len(data)


def test_pcapng_msb_first():
    packet = b"\xaa\xbb\xcc\xdd"
    lsb = section_header() + interface_description() + enhanced_packet(packet)
    msb = (section_header(lsb_first=False) + interface_description(lsb_first=False)
           + enhanced_packet(packet, lsb_first=False))
    assert not is_msb_first(Raw.bytes(lsb))
    assert is_msb_first(Raw.bytes(msb))

    for data in (lsb, msb):
        f = open_data(data)
        blocks = PCAPNGFile.Blocks[f]
        assert [Block.Block_Total_Length[b] for b in blocks] == [28, 20, 36]
        interface = Block.Body.get_choice(blocks[1])
        assert InterfaceDescriptionBlock.LinkType[interface] == LINKTYPE_ETHERNET
        block_2 = Block.Body.get_choice(blocks[2])
        assert EnhancedPacketBlock.Timestamp_High[block_2] == 0x11223344
        assert EnhancedPacketBlock.Captured_Packet_Length[block_2] == 4
        assert EnhancedPacketBlock.Packet_Data[block_2] == Raw.bytes(packet)


def test_pcapng_encode():
    b = Block(Frames.compose())
    Block.Block_Type[b] = BLOCK_ENHANCED_PACKET
    Block.Body.select(b, BlockBody.Enhanced_Packet)
    packet = BlockBody.Enhanced_Packet[Block.Body[b]]
    EnhancedPacketBlock.Timestamp_High[packet] = 0x11223344
    EnhancedPacketBlock.Timestamp_Low[packet] = 0x55667788
    EnhancedPacketBlock.Packet_Data[packet] = Raw.hex("aa bb cc dd")

    # the block total length is calculated and stored to both ends of the block
    encoded = b.encode()
    assert encoded == Raw.bytes(enhanced_packet(b"\xaa\xbb\xcc\xdd"))
    assert Block.Block_Total_Length[b] == Block.Block_Total_Length_2[b] == 36

    b = Block(Frames.dissect(encoded))
    assert Block.Block_Type[b] == BLOCK_ENHANCED_PACKET
    packet = Block.Body.get_choice(b)
    assert EnhancedPacketBlock.Captured_Packet_Length[packet] == 4
    assert EnhancedPacketBlock.Original_Packet_Length[packet] == 4
    assert EnhancedPacketBlock.Packet_Data[packet] == Raw.hex("aa bb cc dd")


def test_pcapng_interfaces():
    # two interfaces of different link types, the packets tell which one they came from
    data = (section_header() + interface_description(LINKTYPE_ETHERNET)
            + interface_description(LINKTYPE_RAW)
            + enhanced_packet(b"\x01\x02", interface_id=1)
            + enhanced_packet(b"\x03\x04", interface_id=0)
            + simple_packet(b"\x05\x06\x07"))
    f = open_data(data)

    packets = [(link_type, packet_data(b)) for b, link_type in PCAPNGPacketIterator(f)]
    assert packets == [(LINKTYPE_RAW, Raw.hex("01 02")),
                       (LINKTYPE_ETHERNET, Raw.hex("03 04")),
                       (LINKTYPE_ETHERNET, Raw.hex("05 06 07"))]  # padding of the simple block cut


def test_pcapng_unknown_interface():
    data = section_header() + interface_description() + enhanced_packet(b"\x01\x02", interface_id=3)
    f = open_data(data)
    with pytest.raises(ValueError, match="interface 3 is not described"):
        list(PCAPNGPacketIterator(f))


def test_pcapng_unmodeled_block():
    # an Interface Statistics Block, which is not modeled, is passed by
    statistics = block(0x00000005, b"\x00" * 12)
    data = section_header() + interface_description() + statistics + enhanced_packet(b"\x01\x02")
    f = open_data(data)

    blocks = PCAPNGFile.Blocks[f]
    assert len(blocks) == 4
    assert Block.Body[blocks[2]].backend.choice == BlockBody.Other
    assert Block.Body.get_choice(blocks[2]) == Raw.hex("00" * 12)

    packets = [(link_type, packet_data(b)) for b, link_type in PCAPNGPacketIterator(f)]
    assert packets == [(LINKTYPE_ETHERNET, Raw.hex("01 02"))]


def test_pcapng_check_format():
    with pytest.raises(ValueError, match="too short to be a PCAPNG file"):
        open_data(bytes(Raw.hex("0a0d0d0a 1c00").as_bytes(0, 6)))

    with pytest.raises(ValueError, match="the first block type is 0x00000001"):
        open_data(interface_description() + section_header())

    bad_magic = block(BLOCK_SECTION_HEADER, b"\x11\x22\x33\x44" + b"\x01\x00\x00\x00" + b"\xff" * 8)
    with pytest.raises(ValueError, match="Unknown PCAPNG Byte-Order Magic 11223344"):
        open_data(bad_magic)

    order = "little"
    body = (BYTE_ORDER_MAGIC.as_bytes(0, 4) + (2).to_bytes(2, order) + (0).to_bytes(2, order)
            + b"\xff" * 8)
    with pytest.raises(ValueError, match="Unsupported PCAPNG file version 2.0"):
        open_data(block(BLOCK_SECTION_HEADER, body))


def test_pcapng_sample_file():
    f = PCAPNGFile.open_file(pathlib.Path("samples/sample-1.pcapng"))

    packets = list(PCAPNGPacketIterator(f))
    assert len(packets) == 2349
    first_block, link_type = packets[0]
    assert link_type == LINKTYPE_ETHERNET
    assert packet_data(first_block).byte_length() == 66

    # the packets are dissected by their own protocols
    eth = EthernetII(Frames.dissect(packet_data(first_block), mappings=Ethernet_Payloads))
    ip = eth / EthernetII.data
    assert isinstance(ip, IPv4)
    assert IPv4.Total_Length[ip] == 0x34

    Frames.close(f)
