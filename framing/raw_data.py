import ipaddress
import mmap
import pathlib
from typing import Iterable, List, BinaryIO, Union


# IP address, shouldn't this be defined by Python?
IPAddress = Union[ipaddress.IPv6Address, ipaddress.IPv4Address]


class LengthEntity:
    def bit_length(self) -> int:
        """Length in bits or -1 if a stream"""
        raise NotImplementedError()

    def byte_length(self) -> int:
        """Length in full bytes or -1 if a stream"""
        return self.bit_length() // 8


class RawData:
    """Raw data buffer"""
    def bit_length(self) -> int:
        raise NotImplementedError()

    def byte_length(self) -> int:
        return self.bit_length() // 8

    def bits_available(self) -> int:
        """Number of bits available without waiting"""
        return self.bit_length()

    def bytes_available(self) -> int:
        """Number of bytes available without waiting"""
        return self.byte_length()

    def read_all(self) -> 'RawData':
        """Read all data so that length is known"""
        return self

    def octet(self, byte_offset: int) -> int:
        """Get octet by offset or -1 if past EOF"""
        raise NotImplementedError()

    def as_bytes(self, byte_offset: int, byte_length: int) -> bytes:
        """Get data as bytes, EOF if not enough available"""
        # NOTE: Default implementation is slow!
        b = bytearray(byte_length)
        for i in range(0, byte_length):
            v = self.octet(byte_offset + i)
            if v < 0:
                raise EOFError("Not enough bytes available")
            b[i] = v
        return b

    def as_ip_address(self) -> IPAddress:
        bl = self.bit_length()
        if bl == 32:
            return ipaddress.IPv4Address(self.as_bytes(0, 4))
        if bl == 128:
            return ipaddress.IPv6Address(self.as_bytes(0, 16))
        raise ValueError(f"Raw data ({self.bit_length()} bits) is not IP address: " + self.to_hex())

    def as_hw_address(self) -> str:
        return ":".join([f"{self.octet(i):02x}" for i in range(0, self.byte_length())])

    def as_string(self, encoding='ascii') -> str:
        return self.as_bytes(0, self.byte_length()).decode(encoding)

    def bit(self, bit_offset: int) -> int:
        """Get bit by offset or -1 if past EOF"""
        octet = self.octet(bit_offset // 8)
        if octet == -1:
            return -1
        shift = 7 - (bit_offset % 8)
        return (octet >> shift) & 1

    def subBlockBits(self, bit_offset: int, bit_length: int) -> 'RawData':
        """Get sub-block, empty if beyond data"""
        if bit_offset % 8 == 0 and bit_length % 8 == 0:
            return self.subBlock(bit_offset // 8, bit_length // 8)
        return BitAlignedData(self, bit_offset, bit_length)

    def subBlock(self, byte_offset: int, byte_length: int) -> 'RawData':
        """Get sub-block, empty if beyond data"""
        raise NotImplementedError()

    def tailBits(self, bit_offset: int) -> 'RawData':
        """Get raw data tail, empty if beyond data"""
        if bit_offset % 8 == 0:
            return self.tailBytes(bit_offset // 8)
        return BitAlignedData(self, bit_offset)

    def tailBytes(self, byte_offset: int) -> 'RawData':
        """Get raw data tail, empty if beyond data"""
        raise NotImplementedError()

    def __repr__(self):
        return self.dump()

    def __bool__(self):
        return self.bit_length() > 0

    def __eq__(self, other):
        if not isinstance(other, RawData):
            return False
        blen = self.bit_length()
        if blen < 0 or other.bit_length() < 0 or (blen != other.bit_length()):
            return False  # streams cannot be compared or different length
        for i in range(0, blen // 8):
            if self.octet(i) != other.octet(i):
                return False
        for i in range(blen // 8 * 8, blen):
            if self.bit(i) != other.bit(i):
                return False
        return True

    def __add__(self, other: 'RawData') -> 'RawData':
        return Raw.sequence([self, other])

    def to_hex(self) -> str:
        """Show as hex string"""
        return "".join([f"{self.octet(i):02x}" for i in range(0, self.byte_length())])

    def dump(self, center_line=False) -> str:
        """Print a classic data dump"""
        if self.bit_length() == 0:
            return "()"
        if self.bit_length() % 8 != 0:
            bl = self.bit_length()
            def div(i: int):
                return i < bl - 1 and (bl - i - 1) % 4 == 0

            return "".join([f"{self.bit(i)}" + (" " if div(i) else "") for i in range(0, bl)])
        lines = (self.byte_length() + 15) // 16
        r = []
        show_wid = 16 if lines > 1 else self.byte_length()
        for li in range(0, lines):
            off = li * 16
            wid = min(16, self.byte_length() - off)
            h_line = ["  "] * (show_wid - wid)
            c_line = [" "]
            for i in range(0, wid):
                octet = self.octet(off + i)
                h_line.append(f"{octet:02x}")
                c_line.append(chr(octet) if 32 < octet < 127 else ".")
            if center_line:
                c_line += " " * (16 - wid)
            line = " ".join(h_line) + " " + "".join(c_line)
            r.append(line)
        return "\n".join(r)

    def close(self) -> 'RawData':
        """Close underlying file, if any"""
        return self


class ByteData(RawData):
    """Bytes"""
    def __init__(self, data, byte_start: int, byte_length: int):
        self.data = data
        self.start = byte_start
        self.length = byte_length

    def bit_length(self) -> int:
        return self.length * 8

    def byte_length(self) -> int:
        return self.length

    def octet(self, byte_offset: int) -> int:
        return self.data[self.start + byte_offset] if byte_offset < self.length else -1

    def as_bytes(self, byte_offset: int, byte_length: int) -> bytes:
        ml = min(byte_length, max(0, self.length - byte_offset))
        if ml < byte_length:
            raise EOFError("Not enough bytes")
        mo = self.start + byte_offset
        return self.data[mo:mo + ml]

    def subBlock(self, byte_offset: int, byte_length: int) -> 'RawData':
        ml = min(byte_length, max(0, self.length - byte_offset))
        return ByteData(self.data, self.start + byte_offset, ml)

    def tailBytes(self, byte_offset: int) -> 'RawData':
        ml = max(0, self.length - byte_offset)
        return ByteData(self.data, self.start + byte_offset, ml)


class RawDataSequence(RawData):
    def __init__(self, components: List[RawData]):
        cs = []
        for c in components:
            if isinstance(c, RawDataSequence):
                cs.extend(c.components)
            else:
                cs.append(c)
        self.components = cs
        self.length = sum([c.bit_length() for c in components])

    def bit_length(self) -> int:
        return self.length

    def byte_length(self) -> int:
        return self.length // 8

    def octet(self, byte_offset: int) -> int:
        off = byte_offset * 8
        for ci, c in enumerate(self.components):
            c_len = c.bit_length()
            if off < c_len:
                if off % 8 == 0 and off + 8 <= c_len:
                    return c.octet(off // 8)
                # octet must be collected bit-by-bit (slow!)
                v = 0
                for i in range(0, 8):
                    if off >= c_len:
                        # next component buffer
                        off = 0
                        ci += 1
                        c = self.components[ci]
                        c_len = c.bit_length()
                    v <<= 1
                    v |= c.bit(off)
                    off += 1
                return v
            off -= c_len
        return -1

    def bit(self, bit_offset: int) -> int:
        off = bit_offset
        for c in self.components:
            c_len = c.bit_length()
            if off < c_len:
                return c.bit(off)
            off -= c_len
        return -1

    def subBlockBits(self, bit_offset: int, bit_length: int) -> 'RawData':
        """Get sub-block"""
        if bit_offset == 0 and bit_length == self.bit_length():
            return self
        off = 0
        end_offset = min(bit_offset + bit_length, self.bit_length())
        nc = []
        for c in self.components:
            c_len = c.bit_length()
            if off >= bit_offset:
                if off >= end_offset:
                    return Raw.sequence(nc)
                s = max(0, off - bit_offset)
                e = min(c_len, end_offset - off)
                nc.append(c.subBlockBits(s, e))
            off += c_len
        return Raw.sequence(nc)

    def subBlock(self, byte_offset: int, byte_length: int) -> 'RawData':
        """Get sub-block"""
        return self.subBlockBits(byte_offset * 8, byte_length * 8)

    def tailBytes(self, byte_offset: int) -> 'RawData':
        return self.tailBits(byte_offset * 8)

    def tailBits(self, bit_offset: int) -> 'RawData':
        """Get raw data tail"""
        if bit_offset == 0:
            return self
        if bit_offset >= self.bit_length():
            return Raw.empty
        off = bit_offset
        for i, c in enumerate(self.components):
            c_len = c.bit_length()
            if off < c_len:
                nc = [c.tailBits(off)]
                nc.extend(self.components[i + 1:])
                return Raw.sequence(nc)
            off -= c_len
        return Raw.empty


class ZeroData(RawData):
    """All bits zero"""
    def __init__(self, bit_length: int):
        self.length = bit_length

    def bit_length(self) -> int:
        return self.length

    def octet(self, byte_offset: int) -> int:
        return 0 if byte_offset < self.length // 8 else -1

    def bit(self, bit_offset: int) -> int:
        return 0 if bit_offset < self.length else -1

    def subBlockBits(self, bit_offset: int, bit_length: int) -> 'RawData':
        ml = min(bit_length, max(0, self.length - bit_offset))
        return ZeroData(ml)

    def subBlock(self, byte_offset: int, byte_length: int) -> 'RawData':
        ml = min(byte_length * 8, max(0, self.length - byte_offset * 8))
        return ZeroData(ml)

    def tailBits(self, bit_offset: int) -> 'RawData':
        ml = max(0, self.length - bit_offset)
        return ZeroData(ml)

    def tailBytes(self, byte_offset: int) -> 'RawData':
        ml = max(0, self.length - byte_offset * 8)
        return ZeroData(ml)


class BitAlignedData(RawData):
    def __init__(self, data: RawData, bit_offset: int, bit_length=-1):
        self.data = data
        self.offset = bit_offset
        self.length = bit_length

    def bit_length(self) -> int:
        if self.length < 0:
            return self.data.bit_length() - self.offset
        return self.length

    def byte_length(self) -> int:
        return self.bit_length() // 8

    def subBlockBits(self, bit_offset: int, bit_length: int) -> 'RawData':
        ml = min(bit_length, max(0, self.length - bit_offset))
        return self.data.subBlockBits(self.offset + bit_offset, ml)

    def subBlock(self, byte_offset: int, byte_length: int) -> 'RawData':
        ml = min(byte_length * 8, max(0, self.length - byte_offset * 8))
        return self.data.subBlockBits(self.offset + byte_offset * 8, ml)

    def tailBits(self, bit_offset: int) -> 'RawData':
        if self.length < 0:
            return self.data.tailBits(self.offset + bit_offset)
        ml = max(0, self.length - bit_offset)
        return self.subBlockBits(self.offset + bit_offset, ml)

    def tailBytes(self, byte_offset: int) -> 'RawData':
        if self.length < 0:
            return self.data.tailBits(self.offset + byte_offset * 8)
        ml = max(0, self.length - byte_offset * 8)
        return self.subBlockBits(self.offset + byte_offset * 8, ml)

    def octet(self, byte_offset: int) -> int:
        if self.length >= 0 and byte_offset >= self.length // 8:
            return -1
        off = self.offset + byte_offset * 8
        shift = off % 8
        if shift == 0:
            return self.data.octet(off)
        byte_off = off // 8
        hi = (self.data.octet(byte_off) << shift) & 0xff
        lo = self.data.octet(byte_off + 1) >> (8 - shift)
        v = hi | lo
        return v

    def bit(self, bit_offset: int) -> int:
        if 0 <= self.length <= bit_offset:
            return -1
        return self.data.bit(self.offset + bit_offset)


class FileData(ByteData):
    def __init__(self, file: BinaryIO, file_path: pathlib.Path):
        b = mmap.mmap(file.fileno(), 0, mmap.MAP_PRIVATE)
        super().__init__(b, 0, len(b))
        self.file = file
        self.file_path = file_path

    def close(self):
        self.file.close()


class Raw:
    """Raw data factory"""

    empty = ZeroData(0)

    @classmethod
    def bytes(cls, data: bytes) -> RawData:
        return ByteData(data, 0, len(data))

    @classmethod
    def octets(cls, *data: int) -> RawData:
        b = bytes(data)
        return ByteData(b, 0, len(b))

    @classmethod
    def string(cls, value: str, encoding='ascii'):
        return cls.bytes(value.encode(encoding))

    @classmethod
    def hex(cls, hex_string: str) -> RawData:
        b = bytes.fromhex(hex_string)
        return ByteData(b, 0, len(b))

    @classmethod
    def bits(cls, bit_string: str) -> RawData:
        bit_string = "".join(bit_string.split())  # remove whitespace
        bit_l = len(bit_string)
        b = bytearray((bit_l + 7) // 8)
        for i, s in enumerate(bit_string):
            b[i // 8] <<= 1
            b[i // 8] += int(s)
        if bit_l % 8 != 0:
            b[-1] <<= (8 - bit_l % 8)
        r = ByteData(b, 0, len(b)).subBlockBits(0, bit_l)
        return r

    @classmethod
    def zeroes(cls, byte_length: int = None, bit_length: int = None) -> RawData:
        if byte_length is not None:
            assert bit_length is None or bit_length == byte_length * 8
            return ZeroData(byte_length * 8)
        if bit_length is not None:
            return ZeroData(bit_length)
        return cls.empty

    @classmethod
    def sequence(cls, components: Iterable[RawData]) -> RawData:
        cs = list(components)
        if not cs:
            return cls.empty
        if len(cs) == 1:
            return cs[0]
        return RawDataSequence(cs)

    @classmethod
    def file(cls, file_path: pathlib.Path) -> FileData:
        f = file_path.open("rb")
        return FileData(f, file_path)
