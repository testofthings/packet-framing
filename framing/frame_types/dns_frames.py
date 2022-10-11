from typing import List

from framing.base import Frame, F, T, FrameBackend
from framing.codecs import IntegerFormat
from framing.fields import Structure, Sequence, ValueOf, LVField, RawField
from framing.raw_data import Raw, RawData


class DNSHeader(Frame):
    structure = Structure['DNSHeader']()

    ID = structure.raw(bits=16)
    QR = structure.raw(bits=1)
    OPCODE = structure.integer(IntegerFormat(bits=4))
    AA = structure.raw(bits=1)
    TC = structure.raw(bits=1)
    RD = structure.raw(bits=1)
    RA = structure.raw(bits=1)
    Z = structure.raw(bits=3)
    RCODE = structure.integer(IntegerFormat(bits=4))
    QDCOUNT = structure.integer((IntegerFormat(bits=16)))
    ANCOUNT = structure.integer((IntegerFormat(bits=16)))
    NSCOUNT = structure.integer((IntegerFormat(bits=16)))
    ARCOUNT = structure.integer((IntegerFormat(bits=16)))


class DNSName(RawField):
    def __init__(self):
        super().__init__(Raw.empty)

    def decode_bit_length(self, data: RawData, bit_offset: int, value: T, backend: FrameBackend) -> int:
        fb = data.octet(bit_offset // 8)
        return 8 + fb * 8 if fb < 0xc0 else 2 * 8

    def decode(self, data: RawData, bit_length, backend: FrameBackend) -> RawData:
        fb = data.octet(0)
        return data.subBlock(0, fb + 1) if fb < 0xc0 else data.subBlock(0, 2)

    @classmethod
    def parse_string(cls, data: RawData, message: 'DNSMessage') -> List[str]:
        """Parse DNS encoded string"""
        ba = message.backend
        fb = data.octet(0)
        r = []
        while fb > 0:
            if fb >= 0xc0:
                # compressed
                offset = fb & 0x3f << 8 | data.octet(1)
                cs = cls.parse_string(ba.input_data().tailBytes(offset), message)
                r.extend(cs)
                break
            else:
                r.append(data.subBlock(1, fb).as_string())
                data = data.tailBytes(1 + fb)
                fb = data.octet(0)
        return r

    @classmethod
    def string(cls, frame: Frame, field: Sequence) -> str:
        """Parse DNS name field value"""
        s = []
        for r in field.get(frame):
            s.extend(cls.parse_string(r, frame.backend.parent.frame))
        return ".".join(s)


def dns_name_end_check(raw: RawData) -> bool:
    """DNS name end check"""
    fb = raw.octet(0)
    return not (0 < fb < 0xc0)


class DNSQuestion(Frame):
    structure = Structure['DNSQuestion']()

    QNAME = Sequence(structure.field(DNSName())).terminator_test(dns_name_end_check)
    QTYPE = structure.integer(IntegerFormat(bytes=2))
    QCLASS = structure.integer(IntegerFormat(bytes=2))


class DNSResource(Frame):
    structure = Structure['DNSResource']()

    NAME = Sequence(structure.field(DNSName())).terminator_test(dns_name_end_check)
    TYPE = structure.integer(IntegerFormat(bytes=2))
    CLASS = structure.integer(IntegerFormat(bytes=2))
    TTL = structure.integer(IntegerFormat(bytes=2))
    RDLENGTH = structure.integer(IntegerFormat(bytes=2))
    RDATA = structure.raw().length_by(ValueOf(RDLENGTH))


class DNSMessage(Frame):
    structure = Structure['DNSMessage']()

    Header = structure.sub(DNSHeader)
    Question = Sequence(structure.sub(DNSQuestion)).count_by(ValueOf(DNSHeader.QDCOUNT))
    Answer = Sequence(structure.sub(DNSResource)).count_by(ValueOf(DNSHeader.ANCOUNT))
    Authority = Sequence(structure.sub(DNSResource)).count_by(ValueOf(DNSHeader.NSCOUNT))
    Additional = Sequence(structure.sub(DNSResource)).count_by(ValueOf(DNSHeader.ARCOUNT))
