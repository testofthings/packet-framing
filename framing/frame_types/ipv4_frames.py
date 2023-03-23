import enum
from typing import Tuple, Optional

from framing.base import Frame, LayerMapping
from framing.codecs import IntegerFormat
from framing.data_queue import RawDataQueue
from framing.fields import Structure, ValueOf
from framing.frame_types.tcp_frames import TCP
from framing.frame_types.udp_frames import UDP
from framing.raw_data import IPAddress, RawData


class IPv4(Frame):
    structure = Structure['IPv4']()

    Version = structure.integer(IntegerFormat(bits=4), default=4)
    IHL = structure.integer(IntegerFormat(bits=4))
    DSCP = structure.integer(IntegerFormat(bits=6))
    ECN = structure.integer(IntegerFormat(bits=2))
    Total_Length = structure.integer(IntegerFormat(bits=16))
    Identification = structure.integer(IntegerFormat(bits=16))
    Flags = structure.integer(IntegerFormat(bits=3))
    Fragment_Offset = structure.integer(IntegerFormat(bits=13))
    TTL = structure.integer(IntegerFormat(bits=8))
    Protocol = structure.integer(IntegerFormat(bits=8))
    Header_Checksum = structure.integer(IntegerFormat(bits=16))
    Source_IP = structure.raw(bits=32)
    Destination_IP = structure.raw(bits=32)

    Options = structure.raw().end_offset_by(ValueOf(IHL) * 4)

    Payload = structure.raw().end_offset_by(ValueOf(Total_Length))

    def get_addresses(self) -> Tuple[IPAddress, IPAddress]:
        """Quick access to source and destination address"""
        return self.backend.get(self.Source_IP).as_ip_address(), self.backend.get(self.Destination_IP).as_ip_address()


class IPv4Flag(enum.IntFlag):
    """IPv4 flag definitions"""
    DF = 0b10  # Don't fragment
    MF = 0b01  # More fragments


IPv4.Flags.flag_values(IPv4Flag)


# Define IP protocol type mappings
IP_Payloads = LayerMapping(IPv4.Payload).by(IPv4.Protocol, {
    0x06: TCP,
    0x11: UDP,
})


class IPv4DefragmentQueue(RawDataQueue):
    """IPv4 defragmented data queue"""
    def __init__(self):
        super().__init__(offset=0)
        self.target_length = 0

    def push_frame(self, ip: IPv4) -> Optional[RawData]:
        more = IPv4.Flags[ip] & IPv4Flag.MF
        offset = IPv4.Fragment_Offset[ip] * 8
        data = IPv4.Payload.as_raw(ip)  # cannot always decode payload, as only fragment
        if offset == 0 and not more:
            return data  # not fragmented
        super().push(data, offset)
        if not more:
            # we now know how much data coming
            self.target_length = offset + data.byte_length()
        if self.target_length and self.head.fixed.byte_length() == self.target_length:
            # we have all data
            self.head.close()
            return self.head
        return None
