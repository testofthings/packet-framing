import typing
from typing import Self

from framing.raw_data import RawData, Raw


V = typing.TypeVar("V")


class ValueCodec(typing.Generic[V]):
    """Base class for integer codecs"""
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


class RawCodec(ValueCodec[RawData]):
    def __init__(self, fixed_bit_length=-1):
        self.fixed_bit_length = fixed_bit_length

    def default_value(self) -> RawData:
        return Raw.empty

    def encode(self, value: RawData) -> RawData:
        return value

    def decode(self, data: RawData) -> RawData:
        return data

    def get_bit_length(self, value: RawData) -> int:
        return value.bit_length()

    def get_fixed_bit_length(self) -> int:
        return self.fixed_bit_length


class IntegerCodec(ValueCodec[int]):
    """Base class for integer codecs"""
    def default_value(self) -> int:
        return 0

    def decode_direct(self, bit_offset: int, data: RawData) -> int:
        """Decode directly from frame data. Caller must know when supported"""
        return self.decode(data.tailBits(bit_offset))


class FixedByteIntegerCodec(IntegerCodec):
    def __init__(self, byte_length: int, little_end=False):
        self.length = byte_length
        self.little_end = little_end
        if little_end:
            self.steps = list(range(byte_length - 1, -1, -1))
        else:
            self.steps = list(range(0, byte_length))
        self.reverse = list(reversed(self.steps))

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
            d = data.tailBits(bit_offset)
            offset = 0
        v = 0
        octet = 0
        for i in self.reverse:
            v <<= 8
            octet = d.octet(offset + i)
            v |= octet
        if octet < 0:
            raise EOFError()  # only check the last part to minimize impact
        return v

    def get_bit_length(self, value: int) -> int:
        return self.length * 8

    def get_fixed_bit_length(self) -> int:
        return self.length * 8


class FixedBitIntegerCodec(IntegerCodec):
    def __init__(self, bit_length: int, little_end=False):
        self.byte_codec = FixedByteIntegerCodec((bit_length + 7) // 8, little_end)
        self.length = bit_length

    def encode(self, value: int) -> RawData:
        b = self.byte_codec.encode(value)
        if self.byte_codec.little_end:
            r = b.tailBits(8 - self.length % 8)
        else:
            r = b.subBlockBits(0, self.length)
        return r

    def decode(self, data: RawData) -> int:
        if self.byte_codec.little_end:
            b = Raw.zeroes(bit_length=8 - self.length % 8) + data
        else:
            b = data + Raw.zeroes(bit_length=8 - self.length % 8)
        return self.byte_codec.decode(b)

    def decode_direct(self, bit_offset: int, data: RawData) -> int:
        octet_off = bit_offset // 8
        l_mask = 0xff >> (bit_offset % 8)
        octet = data.octet(octet_off)
        v = octet & l_mask if l_mask else octet
        for i in range(0, self.length // 8):
            v <<= 8
            octet = data.octet(octet_off + 1 + i)
            v |= octet
        if octet < 0:
            raise EOFError()  # only check the last part to minimize impact
        r_shift = 8 - ((bit_offset + self.length) % 8)
        v = v >> r_shift if r_shift < 8 else v
        if not self.byte_codec.little_end:
            # big endian
            raise NotImplementedError()
        return v

    def get_bit_length(self, value: int) -> int:
        return self.length

    def get_fixed_bit_length(self) -> int:
        return self.length


class IntegerFormat:
    """Codec formatter"""
    def __init__(self, bits=0, bytes=0, big_end: bool = False):
        self.bit_length = bits or (bytes * 8) or 16
        self.little_end = not big_end

    def bits(self, bits: int) -> Self:
        self.bit_length = bits
        return self

    def bytes(self, bytes: int) -> Self:
        self.bit_length = bytes * 8
        return self

    def little_endian(self, flag=True) -> Self:
        self.little_end = flag
        return self

    def big_endian(self, flag=True) -> Self:
        self.little_end = not flag
        return self

    def create_codec(self) -> IntegerCodec:
        if self.bit_length % 8 != 0:
            return FixedBitIntegerCodec(bit_length=self.bit_length, little_end=self.little_end)
        else:
            return FixedByteIntegerCodec(byte_length=self.bit_length // 8, little_end=self.little_end)

