"Value codecs, such as integer codecs"

from abc import ABC
import typing
from typing import Optional, Self

from framing.raw_data import RawData, Raw


V = typing.TypeVar("V")


class ValueCodec(typing.Generic[V]):
    """Base class for value codecs"""
    def default_value(self) -> V:
        """Default value"""
        raise NotImplementedError()

    def encode(self, value: V) -> RawData:
        """Encode!"""
        raise NotImplementedError()

    def decode(self, data: RawData) -> V:
        """Decode!"""
        raise NotImplementedError()

    def get_bit_length(self, value: V) -> int:
        """Get bit length for a value"""
        raise NotImplementedError()

    def get_fixed_bit_length(self) -> int:
        """Get fixed bit length or -1"""
        return -1


class IntegerCodec(ABC, ValueCodec[int]):
    """Base class for integer codecs"""
    def default_value(self) -> int:
        return 0

    def swapped(self) -> Optional['IntegerCodec']:
        """The same codec with the octet order swapped, None when there is no octet order"""
        return None

    def decode_direct(self, bit_offset: int, data: RawData) -> int:
        """Decode directly from frame data. Caller must know when supported"""
        return self.decode(data.tail_bits(bit_offset))


class FixedByteIntegerCodec(IntegerCodec):
    """Fixed byte-length integer codec"""
    def __init__(self, byte_length: int, lsb_first: bool = False):
        self.length = byte_length
        self.lsb_first = lsb_first
        if lsb_first:
            self.steps = list(range(0, byte_length))
        else:
            self.steps = list(range(byte_length - 1, -1, -1))
        self.reverse = list(reversed(self.steps))

    def swapped(self) -> Optional[IntegerCodec]:
        return FixedByteIntegerCodec(self.length, not self.lsb_first)

    def encode(self, value: int) -> RawData:
        b = bytearray(self.length)
        v = value
        for i in self.steps:
            b[i] = v % 256
            v >>= 8
        return Raw.bytes(b)

    def decode(self, data: RawData) -> int:
        return self.decode_direct(0, data)

    def decode_direct(self, bit_offset: int, data: RawData) -> int:
        if bit_offset % 8 == 0:
            d = data
            offset = bit_offset // 8
        else:
            d = data.tail_bits(bit_offset)
            offset = 0
        v = 0
        for i in self.reverse:
            v <<= 8
            v |= d.octet(offset + i)
        if v < 0:
            raise EOFError()  # a missing octet is -1, which makes the whole value negative
        return v

    def get_bit_length(self, value: int) -> int:
        return self.length * 8

    def get_fixed_bit_length(self) -> int:
        return self.length * 8


class FixedBitIntegerCodec(IntegerCodec):
    """Fixed bit-length integer codec"""
    def __init__(self, bit_length: int, lsb_first: bool = False):
        self.byte_codec = FixedByteIntegerCodec((bit_length + 7) // 8, lsb_first)
        self.length = bit_length

    def encode(self, value: int) -> RawData:
        b = self.byte_codec.encode(value)
        if self.byte_codec.lsb_first:
            r = b.sub_block_bits(0, self.length)
        else:
            r = b.tail_bits(8 - self.length % 8)
        return r

    def decode(self, data: RawData) -> int:
        if self.byte_codec.lsb_first:
            b = data + Raw.zeroes(bit_length=8 - self.length % 8)
        else:
            b = Raw.zeroes(bit_length=8 - self.length % 8) + data
        return self.byte_codec.decode(b)

    def decode_direct(self, bit_offset: int, data: RawData) -> int:
        octet_off = bit_offset // 8
        l_mask = 0xff >> (bit_offset % 8)
        octet = data.octet(octet_off)
        if octet < 0:
            raise EOFError()  # masking below would hide the missing octet
        v = octet & l_mask if l_mask else octet
        for i in range(0, self.length // 8):
            v <<= 8
            octet = data.octet(octet_off + 1 + i)
            v |= octet
        if octet < 0:
            raise EOFError()  # only check the last part to minimize impact
        r_shift = 8 - ((bit_offset + self.length) % 8)
        v = v >> r_shift if r_shift < 8 else v
        if self.byte_codec.lsb_first:
            # a bit field which is not a whole number of octets, least significant octet first
            raise NotImplementedError()
        return v

    def get_bit_length(self, value: int) -> int:
        return self.length

    def get_fixed_bit_length(self) -> int:
        return self.length


class IntegerFormat:
    """Codec formatter"""
    def __init__(self, bits: int = 0, bytes: int = 0,  # pylint: disable=redefined-builtin
                 lsb_first: bool = False) -> None:
        self.bit_length = bits or (bytes * 8) or 16
        self.lsb_first = lsb_first  # by default most significant octet first, as in network protocols
        self.swap_end = False

    def bits(self, bits: int) -> Self:
        """Set bit length"""
        self.bit_length = bits
        return self

    def bytes(self, bytes: int) -> Self:  # pylint: disable=redefined-builtin
        """Set byte length"""
        self.bit_length = bytes * 8
        return self

    def swappable(self, flag: bool = True) -> Self:
        """The octet order may be swapped by the data, e.g. told by a magic number.
        Only apply to a format of your own, never to the default format of a field."""
        self.swap_end = flag
        return self

    def create_codec(self) -> IntegerCodec:
        """Create the codec"""
        if self.bit_length % 8 != 0:
            return FixedBitIntegerCodec(bit_length=self.bit_length, lsb_first=self.lsb_first)
        return FixedByteIntegerCodec(byte_length=self.bit_length // 8, lsb_first=self.lsb_first)
