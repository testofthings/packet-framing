import enum
from typing import Tuple

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
    Options = structure.raw().end_offset_by(ValueOf(Data_offset) * 4)
    #Padding = structure.raw().end_offset_by(ValueOf(Data_offset) * 4)
    Data = structure.raw()

    def get_ports(self) -> Tuple[int, int]:
        """Quick access to source and destination ports"""
        return self.backend.get(self.Source_port), self.backend.get(self.Destination_port)


class TCPFlag(enum.IntFlag):
    """TCP flag definitions"""
    NS  = 0b100000000
    CWR = 0b010000000
    ECE = 0b001000000
    URG = 0b000100000
    ACK = 0b000010000
    PSH = 0b000001000
    RST = 0b000000100
    SYN = 0b000000010
    FIN = 0b000000001


TCP.Flags.flag_values(TCPFlag)


