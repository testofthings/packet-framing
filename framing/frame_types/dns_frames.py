from framing.base import Frame
from framing.codecs import IntegerFormat
from framing.fields import Structure, Sequence, ValueOf, LVField
from framing.raw_data import Raw


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


class DNSQuestion(Frame):
    structure = Structure['DNSQuestion']()

    QNAME = Sequence(LVField(structure.raw(), length=IntegerFormat(bits=8))).terminate_by(Raw.empty)
    QTYPE = structure.integer(IntegerFormat(bytes=2))
    QCLASS = structure.integer(IntegerFormat(bytes=2))


class DNSResource(Frame):
    structure = Structure['DNSResource']()

    NAME = Sequence(LVField(structure.raw(), length=IntegerFormat(bits=8))).terminate_by(Raw.empty)
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

