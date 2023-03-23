from typing import Tuple

from framing.base import Frame, LayerMapping
from framing.fields import Structure, ValueOf
from framing.frame_types.ipv4_frames import IP_Payloads
from framing.raw_data import IPAddress


class IPv6(Frame):
    structure = Structure['IPv6']()

    Version = structure.integer(bits=4, default=6)
    Traffic_class = structure.integer(bits=8)
    Flow_label = structure.integer(bits=20)
    Payload_length = structure.integer(bits=16)
    Next_header = structure.integer(bits=8)
    Hop_limit = structure.integer(bits=8)
    Source_address = structure.raw(bytes=16)
    Destination_address = structure.raw(bytes=16)

    Payload = structure.raw().end_offset_by(ValueOf(Payload_length))

    def get_addresses(self) -> Tuple[IPAddress, IPAddress]:
        """Quick access to source and destination address"""
        return self.backend.get(self.Source_address).as_ip_address(), \
            self.backend.get(self.Destination_address).as_ip_address()


class ICMPv6(Frame):
    structure = Structure['ICMPv6']()

    Type = structure.integer(bits=8)
    Code = structure.integer(bits=8)
    Checksum = structure.integer(bits=16)
    Message_Body = structure.raw()


class Fragment(Frame):
    structure = Structure['Fragment']()

    Next_Header = structure.integer(bits=8)
    Reserved = structure.raw(bits=8)
    Fragment_offset = structure.integer(bits=13)
    Res = structure.raw(bits=2)
    M = structure.integer(bits=1)
    Identification = structure.raw(bytes=4)
    # NOTE: Payload starts from middle if Fragment_offset > 0, e.g. UDP headers only in first fragment
    Payload = structure.raw()


IPv6_Payloads = LayerMapping(base=IP_Payloads).many_by({
    IPv6.Payload: IPv6.Next_header,
    Fragment.Payload: Fragment.Next_Header,
}, {
    0x2c: Fragment,
    0x3a: ICMPv6,
})
