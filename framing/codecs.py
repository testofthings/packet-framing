from typing_extensions import Self

from framing.raw_data import RawData, Raw


class IntegerCodec:
    """Base class for integer codecs"""
    def encode(self, value: int) -> RawData:
        """Encode!"""
        raise NotImplementedError()

    def decode(self, data: RawData) -> int:
        """Decode!"""
        raise NotImplementedError()

    def get_bit_length(self, value: int) -> int:
        """Get bit length for a value"""
        raise NotImplementedError()

    def get_fixed_bit_length(self) -> int:
        """Get fixed bit length or -1"""
        return -1


class FixedByteIntegerCodec(IntegerCodec):
    def __init__(self, byte_length: int, little_end=False):
        self.length = byte_length
        if little_end:
            self.lo_index = byte_length - 1
            self.hi_index = 0
            self.index_step = -1
        else:
            self.lo_index = 0
            self.hi_index = byte_length - 1
            self.index_step = 1

    def encode(self, value: int) -> RawData:
        b = bytearray(self.length)
        v = value
        for i in range(self.lo_index, self.hi_index + self.index_step, self.index_step):
            b[i] = v % 256
            v >>= 8
        return Raw.bytes(b)

    def decode(self, data: RawData) -> int:
        v = 0
        for i in range(self.hi_index, self.lo_index - self.index_step, -self.index_step):
            v <<= 8
            v |= data.octet(i)
        return v

    def get_bit_length(self, value: int) -> int:
        return self.length * 8

    def get_fixed_bit_length(self) -> int:
        return self.length * 8


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
            raise NotImplementedError("Only full-byte integers supported now")
        return FixedByteIntegerCodec(byte_length=self.bit_length // 8, little_end=self.little_end)

