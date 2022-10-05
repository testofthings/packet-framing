from framing.base import Frame
from framing.codecs import IntegerFormat
from framing.fields import Structure, ValueOf


# https://www.ietf.org/rfc/rfc793.txt

class TCP(Frame):
    structure = Structure()

    Source_port = structure.integer(IntegerFormat(bits=16))
    Destination_port = structure.integer(IntegerFormat(bits=16))
    Sequence_number = structure.integer(IntegerFormat(bits=32))
    Ack_number = structure.integer(IntegerFormat(bits=32))
    Data_offset = structure.integer(IntegerFormat(bits=4))
    Reserved = structure.integer(IntegerFormat(bits=3))
    Flags = structure.integer(IntegerFormat(bits=9))
    Window = structure.integer(IntegerFormat(bits=16))
    Checksum = structure.raw(bits=16)
    Urgent_Pointer = structure.integer(IntegerFormat(bits=16))
    Options = structure.raw()
    Padding = structure.raw().end_offset_by(ValueOf(Data_offset) * 4)
    Data = structure.raw()

