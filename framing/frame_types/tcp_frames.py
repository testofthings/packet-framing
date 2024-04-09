import enum
from typing import Dict, Set, Tuple, Optional

from framing.base import Frame
from framing.codecs import IntegerFormat
from framing.data_queue import RawDataQueue
from framing.fields import Structure, ValueOf
from framing.raw_data import Raw, RawData


# https://www.ietf.org/rfc/rfc793.txt

class TCP(Frame):
    structure = Structure['TCP']()

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
    # Padding = structure.raw().end_offset_by(ValueOf(Data_offset) * 4)
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

# TCP stream id: source IP address, source port, destination IP address, destination port
TCP_Stream_Id = Tuple[RawData, int, RawData, int]
# Null TCP stream id
TCP_Null_Stream_Id = Tuple[Raw.empty, 0, Raw.empty, 0]

def flip_tcp_stream_id(stream_id: TCP_Stream_Id) -> TCP_Stream_Id:
    """Flip TCP stream id"""
    return stream_id[2], stream_id[3], stream_id[0], stream_id[1]


class TCPDataQueue(RawDataQueue):
    """TCP data queue, one connection to one direction"""
    def __init__(self, start: TCP):
        super().__init__(offset=TCP.Sequence_number[start], modulus=2 ** 32)
        if TCP.Flags[start] & TCPFlag.SYN:
            self.offset += 1
        self.end_offset = -1

    def push_frame(self, tcp: TCP) -> RawData:
        """Push tcp frame"""
        data = TCP.Data[tcp]
        offset = TCP.Sequence_number[tcp]
        super().push(data, offset=offset)
        flags = TCP.Flags[tcp]
        if flags & TCPFlag.FIN or flags & TCPFlag.RST:
            self.end_offset = offset + data.byte_length()
        if -1 < self.end_offset <= self.offset + self.available():
            self.close()
        return data
