from typing import Optional

from framing.base import Frame, F, T, FrameBackend
from framing.codecs import IntegerFormat
from framing.fields import Structure, Sequence, ValueOf, LVField, IntField, RawField
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


class DNSName(LVField[F, RawData]):
    def __init__(self):
        super().__init__(RawField(Raw.empty), length=IntegerFormat(bits=8))

    def get_bit_length(self, frame: F, value: Optional[T] = None) -> int:

        # FIXME: A stud for testing
        if value and value.byte_length() == 2:
            return 2

        return super().get_bit_length(frame, value)

    def decode(self, data: RawData, backend: FrameBackend) -> RawData:
        fb = data.octet(0)
        if fb < 0xc0:
            r = super().decode(data, backend)
            return r
        # DNS name compression
        # offset = data.octet(1)
        return backend.input_data().subBlock(0, 2)


class DNSQuestion(Frame):
    structure = Structure['DNSQuestion']()

    QNAME = Sequence(structure.field(DNSName())).terminate_by(Raw.empty)
    QTYPE = structure.integer(IntegerFormat(bytes=2))
    QCLASS = structure.integer(IntegerFormat(bytes=2))


class DNSResource(Frame):
    structure = Structure['DNSResource']()

    NAME = Sequence(structure.field(DNSName())).terminate_by(Raw.empty)
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
