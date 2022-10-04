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
    bb = b.subBlockBits(4, 16)
    assert bb.octet(0) == 0x3a
    assert bb.octet(1) == 0xd1
    assert bb == Raw.hex("3ad1")

    bb = bb.subBlockBits(4, 8)
    assert isinstance(bb, ByteData)
    assert bb.octet(0) == 0xad
    assert bb == Raw.hex("ad")

    bb = b.tailBits(17)
    assert f"{bb}" == "001 0101"


def test_merged_data():
    b = Raw.sequence([Raw.hex("01 02"), Raw.hex("03 04 05")])
    assert b.bit_length() == 5 * 8
    assert b.byte_length() == 5
    assert b == Raw.hex("01 02 03 04 05")
    assert b != Raw.hex("01 02 03 04 ff")

    b2 = b.tailBytes(1)
    assert b2 == Raw.hex("02 03 04 05")

    b2 = b.tailBytes(3)
    assert b2 == Raw.hex("04 05")

    b2 = b.tailBytes(10)
    assert b2 == Raw.empty

    assert b.subBlockBits(5, 0) == Raw.empty
    assert b.subBlockBits(5, 5) == Raw.empty
    assert b.subBlockBits(10, 0) == Raw.empty
    assert b.subBlockBits(10, 2) == Raw.empty
    assert b.tailBits(5 * 8) == Raw.empty
    assert b.tailBits(15 * 8) == Raw.empty

    b = Raw.sequence([Raw.hex("10"), Raw.bits("1"), Raw.hex("10")])
    assert b.octet(0) == 0x10
    assert b.octet(1) == 0x88



def test_file():
    b = Raw.file(pathlib.Path("samples/hello-world.txt"))
    assert b == Raw.hex("48 65 6c 6c 6f 2c 20 77 6f 72 6c 64 21 0a")
    assert b.byte_length() == 14
