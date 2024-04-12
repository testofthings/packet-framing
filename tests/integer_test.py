from framing.codecs import IntegerFormat
from framing.raw_data import Raw


def test_fixed_byte_int():
    codec = IntegerFormat(octets=3).create_codec()
    assert codec.encode(3) == Raw.hex("00 00 03")
    assert codec.decode(Raw.hex("01 00 02")) == 0x010002

    codec = IntegerFormat(octets=3, big_end=True).create_codec()
    assert codec.encode(3) == Raw.hex("03 00 00")
    assert codec.decode(Raw.hex("01 00 02")) == 0x020001


def test_fixed_bit_int():
    codec = IntegerFormat(bits=4).create_codec()
    b0 = codec.encode(4)
    b1 = Raw.bits("0100")
    assert b0 == b1

    assert codec.encode(1) == Raw.bits("0001")
    assert codec.encode(0) == Raw.bits("0000")
    assert codec.encode(14) == Raw.bits("1110")

    assert codec.decode(b1)


def test_direct_one_bit_int():
    codec = IntegerFormat(bits=1).create_codec()
    assert codec.decode_direct(0, Raw.hex("7f")) == 0
    assert codec.decode_direct(0, Raw.hex("80")) == 1
    assert codec.decode_direct(1, Raw.hex("bf")) == 0
    assert codec.decode_direct(1, Raw.hex("40")) == 1
    assert codec.decode_direct(2, Raw.hex("df")) == 0
    assert codec.decode_direct(2, Raw.hex("20")) == 1
    assert codec.decode_direct(7, Raw.hex("fe")) == 0
    assert codec.decode_direct(7, Raw.hex("01")) == 1


def test_direct_int():
    raw = Raw.hex("11 00 3e 38 96")
    codec = IntegerFormat(bits=8).create_codec()
    assert codec.decode_direct(0, raw) == 0x11
    assert codec.decode_direct(4, raw) == 0x10
    assert codec.decode_direct(8, raw) == 0x00
    assert codec.decode_direct(12, raw) == 0x03
    assert codec.decode_direct(16, raw) == 0x3e
