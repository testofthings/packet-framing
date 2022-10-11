from typing import List

from framing.base import Frame, T, FrameBackend, LayerMapping
from framing.fields import Structure, Sequence, ValueOf, RawField
from framing.raw_data import Raw, RawData


class DNSHeader(Frame):
    structure = Structure['DNSHeader']()

    ID = structure.raw(bits=16)
    QR = structure.raw(bits=1)
    OPCODE = structure.integer(bits=4)
    AA = structure.raw(bits=1)
    TC = structure.raw(bits=1)
    RD = structure.raw(bits=1)
    RA = structure.raw(bits=1)
    Z = structure.raw(bits=3)
    RCODE = structure.integer(bits=4)
    QDCOUNT = structure.integer(bits=16)
    ANCOUNT = structure.integer(bits=16)
    NSCOUNT = structure.integer(bits=16)
    ARCOUNT = structure.integer(bits=16)


class NameComponent(RawField):
    """DNS name component"""
    def __init__(self):
        super().__init__(Raw.empty)

    def decode_bit_length(self, data: RawData, bit_offset: int, value: T, backend: FrameBackend) -> int:
        fb = data.octet(bit_offset // 8)
        return 8 + fb * 8 if fb < 0xc0 else 2 * 8

    def decode(self, data: RawData, bit_length, backend: FrameBackend) -> RawData:
        fb = data.octet(0)
        return data.subBlock(0, fb + 1) if fb < 0xc0 else data.subBlock(0, 2)


class DNSName(Sequence):
    """Convenience field type for DNS name"""
    def __init__(self, structure: Structure):
        super().__init__(structure.field(NameComponent()))
        self.terminator_test(self.end_check)

    @classmethod
    def end_check(cls, raw: RawData) -> bool:
        """DNS name end check"""
        fb = raw.octet(0)
        return not (0 < fb < 0xc0)

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
        msg = frame  # find DNS message
        while not isinstance(msg, DNSMessage):
            msg = msg.backend.parent.frame
        for r in field.get(frame):
            s.extend(cls.parse_string(r, msg))
        return ".".join(s)


class DNSQuestion(Frame):
    structure = Structure['DNSQuestion']()

    QNAME = DNSName(structure)
    QTYPE = structure.integer(bytes=2)
    QCLASS = structure.integer(bytes=2)


class DNSResource(Frame):
    structure = Structure['DNSResource']()

    NAME = DNSName(structure)
    TYPE = structure.integer(bytes=2)
    CLASS = structure.integer(bytes=2)
    TTL = structure.integer(bytes=4)
    RDLENGTH = structure.integer(bytes=2)
    RDATA = structure.raw().length_by(ValueOf(RDLENGTH))


class DNSMessage(Frame):
    structure = Structure['DNSMessage']()

    Header = structure.sub(DNSHeader)
    Question = Sequence(structure.sub(DNSQuestion)).count_by(DNSHeader.QDCOUNT.of(Header))
    Answer = Sequence(structure.sub(DNSResource)).count_by(DNSHeader.ANCOUNT.of(Header))
    Authority = Sequence(structure.sub(DNSResource)).count_by(DNSHeader.NSCOUNT.of(Header))
    Additional = Sequence(structure.sub(DNSResource)).count_by(DNSHeader.ARCOUNT.of(Header))


class Name_RDATA(Frame):
    structure = Structure['Name_RDATA']()

    Name = DNSName(structure)


class A_RDATA(Frame):
    structure = Structure['A_RDATA']()

    ADDRESS = structure.raw(bytes=4)


class AAAA_RDATA(Frame):
    structure = Structure['AAAA_RDATA']()

    ADDRESS = structure.raw(bytes=16)


class SOA_RDATA(Frame):
    structure = Structure['SOA_RDATA']()

    MNAME = DNSName(structure)
    RNAME = DNSName(structure)
    SERIAL = structure.integer(bytes=4)
    REFRESH = structure.integer(bytes=4)
    RETRY = structure.integer(bytes=4)
    EXPIRE = structure.integer(bytes=4)


RDATA_Types = LayerMapping(DNSResource.RDATA).by(DNSResource.TYPE, {
    1: A_RDATA,
    2: Name_RDATA,
    5: Name_RDATA,
    6: SOA_RDATA,
    28: AAAA_RDATA,
})

