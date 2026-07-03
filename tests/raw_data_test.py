import ipaddress
import pathlib

from framing.raw_data import Raw, ByteData


def test_bits():
    b = Raw.hex("13ad")
    assert b.bit(0) == 0
    assert b.bit(1) == 0
    assert b.bit(2) == 0
    assert b.bit(3) == 1
    assert b.bit(4) == 0
    assert b.bit(5) == 0
    assert b.bit(6) == 1
    assert b.bit(7) == 1
    assert b.bit(12) == 1
    assert b.bit(14) == 0
    assert b.bit(15) == 1
    assert b.bit(16) == -1
    assert b.bit(152323) == -1


def test_bit_alignment():
    b = Raw.hex("13ad15")
    bb = b.sub_block_bits(4, 16)
    assert bb.octet(0) == 0x3a
    assert bb.octet(1) == 0xd1
    assert bb == Raw.hex("3ad1")
    assert bb.as_bytes(0, 2) == bytes.fromhex("3ad1")

    bb = bb.sub_block_bits(4, 8)
    assert isinstance(bb, ByteData)
    assert bb.octet(0) == 0xad
    assert bb == Raw.hex("ad")

    bb = b.tail_bits(17)
    assert f"{bb}" == "001 0101"


def test_merged_data():
    b = Raw.sequence([Raw.hex("01 02"), Raw.hex("03 04 05")])
    assert b.bit_length() == 5 * 8
    assert b.byte_length() == 5
    assert b == Raw.hex("01 02 03 04 05")
    assert b != Raw.hex("01 02 03 04 ff")
    assert b.as_bytes(1, 4) == bytes.fromhex("02030405")

    b2 = b.tail_bytes(1)
    assert b2 == Raw.hex("02 03 04 05")

    b2 = b.tail_bytes(3)
    assert b2 == Raw.hex("04 05")

    b2 = b.tail_bytes(10)
    assert b2 == Raw.empty

    assert b.sub_block_bits(0, 8) == Raw.octets(0x01)
    assert b.sub_block_bits(8, 8) == Raw.octets(0x02)
    assert b.sub_block_bits(16, 8) == Raw.octets(0x03)
    assert b.sub_block_bits(24, 8) == Raw.octets(0x04)
    assert b.sub_block_bits(32, 8) == Raw.octets(0x05)

    assert b.sub_block_bits(5, 0) == Raw.empty
    assert b.sub_block_bits(5, 5) == Raw.bits("00100")
    assert b.sub_block_bits(10, 0) == Raw.empty
    assert b.sub_block_bits(10, 2) == Raw.bits("00")
    assert b.tail_bits(5 * 8) == Raw.empty
    assert b.tail_bits(15 * 8) == Raw.empty

    b = Raw.sequence([Raw.hex("10"), Raw.bits("1"), Raw.hex("10")])
    assert b.octet(0) == 0x10
    assert b.octet(1) == 0x88


def test_file():
    b = Raw.file(pathlib.Path("samples/hello-world.txt"))
    assert b == Raw.hex("48 65 6c 6c 6f 2c 20 77 6f 72 6c 64 21 0a")
    assert b.byte_length() == 14


def test_stream():
    b = Raw.stream(pathlib.Path("samples/hello-world.txt").open("rb"))
    b.request_size = 5
    assert b.bytes_available() == 0
    assert b.octet(1) == 0x65
    assert b.bytes_available() == 5
    assert b.octet(4) == 0x6f
    assert b.bytes_available() == 5
    assert b.octet(5) == 0x2c
    assert b.bytes_available() == 10

    assert b == Raw.hex("48 65 6c 6c 6f 2c 20 77 6f 72 6c 64 21 0a")
    assert b.bytes_available() == 14
    assert b.byte_length() == 14


def test_ip_address():
    assert Raw.hex("01020304").as_ip_address() == ipaddress.ip_address("1.2.3.4")
    assert Raw.hex("00000000 00000000 00000000 00000001").as_ip_address() == ipaddress.ip_address("::1")
