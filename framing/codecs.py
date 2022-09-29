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


class FixedLittleEndianCodec(IntegerCodec):
    def __init__(self, byte_length: int):
        self.length = byte_length

    def encode(self, value: int) -> RawData:
        b = bytearray(self.length)
        v = value
        for i in range(self.length, 0, -1):
            b[i - 1] = v % 256
            v >>= 8
        return Raw.bytes(b)

    def decode(self, data: RawData) -> int:
        v = 0
        for i in range(0, self.length):
            v <<= 8
            v |= data.octet(i)
        return v

    def get_bit_length(self, value: int) -> int:
        return self.length * 8

    def get_fixed_bit_length(self) -> int:
        return self.length * 8


class IntegerFormat:
    """Codec formatter"""
    def __init__(self, bits=0, bytes=0, little_end: bool = False):
        self.bit_length = bits or (bytes * 8) or 16
        self.little_end = little_end

    def bits(self, bits: int) -> Self:
        self.bit_length = bits
        return self

    def bytes(self, bytes: int) -> Self:
        self.bit_length = bytes * 8
        return self

    def little_end(self, flag=True) -> Self:
        self.little_end = flag
        return self

    def big_end(self, flag=True) -> Self:
        self.little_end = not flag
        return self

    def create_codec(self) -> IntegerCodec:
        if self.bit_length % 8 != 0:
            raise NotImplementedError("Only full-byte integers supported now")
        return FixedLittleEndianCodec(byte_length=self.bit_length // 8)

