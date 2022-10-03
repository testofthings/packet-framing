from framing.base import Frame
from framing.codecs import IntegerFormat
from framing.fields import Structure, ValueOf


class IPv4(Frame):
    structure = Structure['IPv4']()

    Version = structure.integer(IntegerFormat(bits=4), default=4)
    IHL = structure.integer(IntegerFormat(bits=4))
    DSCP = structure.integer(IntegerFormat(bits=6))
    ECN = structure.integer(IntegerFormat(bits=2))
    Total_Length = structure.integer(IntegerFormat(bits=16))
    Identification = structure.integer(IntegerFormat(bits=16))
    Flag = structure.integer(IntegerFormat(bits=3))
    Fragment_Offset = structure.integer(IntegerFormat(bits=13))
    TTL = structure.integer(IntegerFormat(bits=8))
    Protocol = structure.integer(IntegerFormat(bits=8))
    Header_Checksum = structure.integer(IntegerFormat(bits=16))
    Source_IP = structure.raw(bits=32)
    Destination_IP = structure.raw(bits=32)

    Options = structure.raw()

    Payload = structure.raw()

    Destination_IP.end_offset_by(ValueOf(IHL) * 4)
    Payload.end_offset_by(ValueOf(Total_Length))

