from framing.base import Frame
from framing.codecs import IntegerFormat
from framing.fields import Structure, ValueOf


class UDP(Frame):
    structure = Structure['UDP']()

    Source_port = structure.integer(IntegerFormat(bits=16))
    Destination_port = structure.integer(IntegerFormat(bits=16))
    Length = structure.integer(IntegerFormat(bits=16))
    Checksum = structure.raw(bits=16)
    Data = structure.raw().end_offset_by(ValueOf(Destination_port))

