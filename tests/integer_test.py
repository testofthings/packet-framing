import pytest

from framing.codecs import IntegerFormat
from framing.raw_data import Raw


def test_fixed_byte_int():
    codec = IntegerFormat(bytes=3).create_codec()
    assert codec.encode(3) == Raw.hex("00 00 03")
    assert codec.decode(Raw.hex("01 00 02")) == 0x010002

    codec = IntegerFormat(bytes=3, lsb_first=True).create_codec()
    assert codec.encode(3) == Raw.hex("03 00 00")
    assert codec.decode(Raw.hex("01 00 02")) == 0x020001


def test_swapped_codec():
    codec = IntegerFormat(bytes=3).create_codec()
    swapped = codec.swapped()
    assert swapped is not None
    assert swapped.encode(3) == Raw.hex("03 00 00")
    assert swapped.decode(Raw.hex("01 00 02")) == 0x020001
    assert codec.decode(Raw.hex("01 00 02")) == 0x010002  # the original codec is not changed

    # swapping twice gives the original order
    again = swapped.swapped()
    assert again is not None
    assert again.decode(Raw.hex("01 00 02")) == 0x010002

    # a field which is not a whole number of octets has no octet order
    assert IntegerFormat(bits=4).create_codec().swapped() is None
    assert IntegerFormat(bits=13).create_codec().swapped() is None


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


def test_truncated_integer():
    # a missing octet is detected in both octet orders
    for lsb_first in (False, True):
        codec = IntegerFormat(bytes=4, lsb_first=lsb_first).create_codec()
        assert codec.decode(Raw.hex("01 02 03 04")) is not None
        with pytest.raises(EOFError):
            codec.decode(Raw.hex("01 02"))
