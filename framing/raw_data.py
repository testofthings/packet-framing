from typing import Iterable, List


class RawData:
    """Raw data buffer"""
    def bit_length(self) -> int:
        """Length in bits"""
        raise NotImplementedError()

    def byte_length(self) -> int:
        """Length in full bytes"""
        return self.bit_length() // 8

    def octet(self, byte_offset: int) -> int:
        raise NotImplementedError()

    def __repr__(self):
        if self.bit_length() == 0:
            return "()"
        if self.bit_length() % 8 != 0:
            return f"Bit-data length={self.bit_length()} bits"
        return " ".join([f"{self.octet(o):02x}" for o in range(0, self.byte_length())])

    def __bool__(self):
        return self.bit_length() > 0


class ByteData(RawData):
    """Bytes"""
    def __init__(self, data: bytes):
        self.data = data

    def bit_length(self) -> int:
        return len(self.data) * 8

    def byte_length(self) -> int:
        return len(self.data)

    def octet(self, byte_offset: int) -> int:
        return self.data[byte_offset]


class MergedData(RawData):
    def __init__(self, components: List[RawData]):
        self.components = components
        self.length = sum([c.bit_length() for c in components])
        assert self.length % 8 == 0, "Not supporting merging of bit-data blocks"

    def bit_length(self) -> int:
        return self.length

    def byte_length(self) -> int:
        return self.length // 8

    def octet(self, byte_offset: int) -> int:
        off = byte_offset
        for c in self.components:
            c_len = c.byte_length()
            if off < c_len:
                return c.octet(off)
            off -= c_len
        assert "Offset out of range"


class ZeroData(RawData):
    """All bits zero"""
    def __init__(self, bit_length: int):
        self.length = bit_length

    def bit_length(self) -> int:
        return self.length

    def octet(self, byte_offset: int) -> int:
        return 0


class Raw:
    """Raw data factory"""

    empty = ZeroData(0)

    @classmethod
    def bytes(cls, data: bytes) -> RawData:
        return ByteData(data)

    @classmethod
    def hex(cls, hex_string: str) -> RawData:
        return ByteData(bytes.fromhex(hex_string))

    @classmethod
    def zeroes(cls, byte_length: int = None, bit_length: int = None) -> RawData:
        if byte_length is not None:
            assert bit_length is None or bit_length == byte_length * 8
            return ZeroData(byte_length * 8)
        if bit_length is not None:
            return ZeroData(bit_length)
        return cls.empty

    @classmethod
    def merge(cls, components: Iterable[RawData]) -> RawData:
        return MergedData(list(components))

