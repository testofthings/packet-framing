from framing.codecs import IntegerFormat
from framing.raw_data import Raw


def test_fixed_byte_int():
    codec = IntegerFormat(bytes=3).create_codec()
    assert codec.encode(3) == Raw.hex("00 00 03")
    assert codec.decode(Raw.hex("01 00 02")) == 0x010002

    codec = IntegerFormat(bytes=3, big_end=True).create_codec()
    assert codec.encode(3) == Raw.hex("03 00 00")
    assert codec.decode(Raw.hex("01 00 02")) == 0x020001
