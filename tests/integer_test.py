from framing.codecs import IntegerFormat
from framing.raw_data import Raw


def test_fixed_byte_int():
    codec = IntegerFormat(bytes=3).create_codec()
    assert codec.encode(3) == Raw.hex("00 00 03")
    assert codec.decode(Raw.hex("01 00 02")) == 0x010002

    codec = IntegerFormat(bytes=3, big_end=True).create_codec()
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
