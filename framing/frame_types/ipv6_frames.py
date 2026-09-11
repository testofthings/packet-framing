"""IPv6 frame definition and related types"""

from enum import IntEnum
from typing import Any, Iterable, Tuple, Dict, Optional, Type, Union

from framing.backends import RawFrame
from framing.base import Frame, LayerMapping
from framing.data_queue import RawDataQueue
from framing.fields import ConfigurableField, Selection, Structure, ValueOf
from framing.frame_types.ipv4_frames import IP_Payloads, IPv4, IPv4Flag
from framing.frames import Frames
from framing.layer_stack import StackLayer, StackState
from framing.raw_data import IPAddress, Raw, RawData

# pylint: disable=invalid-name

class ExtensionHeader(Frame):
    """IPv6 extension headers"""
    structure = Selection['ExtensionHeader']()

    # Choices completed after frame classes defined
    Payload = structure.raw()  # default
    Hop_by_Hop_Options: ConfigurableField['ExtensionHeader', Frame]
    Routing: ConfigurableField['ExtensionHeader', Frame]
    Fragment: ConfigurableField['ExtensionHeader', Frame]
    ICMPv6: ConfigurableField['ExtensionHeader', Frame]
    IPv6: ConfigurableField['ExtensionHeader', Frame]


def _finish_choice(next_header: int, header_frame: Type[Frame]) -> ConfigurableField[ExtensionHeader, Frame]:
    """Finish extension header choice"""
    return ExtensionHeader.structure.choice(next_header, ExtensionHeader.structure.sub(header_frame))


class IPv6ExtensionHeader(Frame):
    """Other IPv6 extension header"""
    structure = Structure['IPv6ExtensionHeader']()

    Next_Header = structure.integer(bits=8)
    Header_Ext_Length = structure.integer(bits=8)
    Options = structure.raw().end_offset_by((ValueOf(Header_Ext_Length) + 1) * 8)
    Payload = structure.sub(ExtensionHeader).choice_by(Next_Header)


class ICMPv6(Frame):
    """ICMPv6 packet"""
    structure = Structure['ICMPv6']()

    Type = structure.integer(bits=8)
    Code = structure.integer(bits=8)
    Checksum = structure.integer(bits=16)
    Message_Body = structure.raw()


class Fragment(Frame):
    """IPv6 Fragment header"""
    structure = Structure['Fragment']()

    Next_Header = structure.integer(bits=8)
    Reserved = structure.raw(bits=8)
    Fragment_offset = structure.integer(bits=13)
    Res = structure.raw(bits=2)
    M = structure.integer(bits=1)
    Identification = structure.raw(bytes=4)
    # NOTE: Payload starts from middle if Fragment_offset > 0, e.g. UDP headers only in first fragment
    Payload = structure.raw()



class IPv6(Frame):
    """IPv6 packet"""
    structure = Structure['IPv6']()

    Version = structure.integer(bits=4, default=6)
    Traffic_class = structure.integer(bits=8)
    Flow_label = structure.integer(bits=20)
    Payload_length = structure.integer(bits=16)
    Next_header = structure.integer(bits=8)
    Hop_limit = structure.integer(bits=8)
    Source_address = structure.raw(bytes=16)
    Destination_address = structure.raw(bytes=16)
    Payload = structure.sub(ExtensionHeader).choice_by(Next_header).length_by(ValueOf(Payload_length))

    def get_addresses(self) -> Tuple[IPAddress, IPAddress]:
        """Quick access to source and destination address"""
        return self.backend.get(self.Source_address).as_ip_address(), \
            self.backend.get(self.Destination_address).as_ip_address()


    def get_payload(self) -> Tuple[int, Frame]:
        """Quick access to the payload"""
        frame_type = self.Next_header[self]
        frame: Frame = self.Payload[self]
        while True:
            match frame:
                case ExtensionHeader():
                    frame = Selection.frame(frame)
                case IPv6ExtensionHeader():
                    frame_type = IPv6ExtensionHeader.Next_Header[frame]
                    frame = IPv6ExtensionHeader.Payload[frame]
                # case IPv6() if frame_type == 41:
                #     frame_type = 6
                case _:
                    return frame_type, frame


# IPv6 next header values
# http://www.tcpipguide.com/free/t_IPv6DatagramMainHeaderFormat-2.htm
#  01 1 ICMPv4
#  02 2 IGMPv4
#  04 4 IP in IP Encapsulation
#  06 6 TCP
#  08 8 EGP
#  11 17 UDP
#  29 41 IPv6
#  2B 43 Routing Extension Header
#  2C 44 Fragmentation Extension Header
#  2E 46 Resource Reservation Protocol (RSVP)
#  32 50 Encrypted Security Payload (ESP) Extension Header
#  33 51 Authentication Header (AH) Extension Header
#  3A 58 ICMPv6
#  3B 59 No Next Header
#  3C 60 Destination Options Extension Header
class Header(IntEnum):
    """IPv6 next header value enumeration"""
    Hop_by_Hop_Options = 0
    IPv4 = 4
    Routing = 43
    Fragment = 44
    ICMPv6 = 58
    IPv6 = 41


# Extension header frame classes defined, complete choice
ExtensionHeader.Hop_by_Hop_Options = _finish_choice(Header.Hop_by_Hop_Options, IPv6ExtensionHeader)
ExtensionHeader.Routing = _finish_choice(Header.Routing, IPv6ExtensionHeader)
ExtensionHeader.Fragment = _finish_choice(Header.Fragment, Fragment)
ExtensionHeader.ICMPv6 = _finish_choice(Header.ICMPv6,  ICMPv6)
ExtensionHeader.IPv6 = _finish_choice(Header.IPv6, IPv6)


IPv6_Payloads = LayerMapping(base=IP_Payloads).many_by({
    IPv6.Payload: IPv6.Next_header,
    Fragment.Payload: Fragment.Next_Header,
    IPv6ExtensionHeader.Payload: IPv6ExtensionHeader.Next_Header,
}, {
    Header.Hop_by_Hop_Options: IPv6ExtensionHeader,
    Header.Routing: IPv6ExtensionHeader,
    Header.Fragment: Fragment,
    Header.ICMPv6: ICMPv6,
    Header.IPv6: IPv6,
})


# Either IPv4 or IPv6
IPx = Union[IPv4 | IPv6]


def ip_frame_type(data: RawData) -> Type[Frame]:
    """Pick IPv4 or IPv6 by the version nibble."""
    version = data.octet(0) >> 4
    if version == 4:
        return IPv4
    if version == 6:
        return IPv6
    raise ValueError(f"Unknown IP version {version}")


class IPReassembler:
    """IPx reassembler"""
    def __init__(self) -> None:
        self.queues: Dict[Tuple[RawData, RawData, RawData], Tuple[RawDataQueue, int]] = {}

    def push_frame(self, ip: IPx) -> Optional[Frame]:
        """Push IP frame, get back frame, if possible"""
        r = self.push(ip)
        if r is None:
            return None
        field = IPv6.Payload if isinstance(ip, IPv6) else IPv4.Payload
        out = IPv6_Payloads.decode_payload(ip, field, payload_type=r[0], data=r[1])
        return out or RawFrame(Frames.dissect(r[1]))

    def push(self, ip: IPx) -> Optional[Tuple[Optional[int], RawData]]:
        """Push IP frame, get back reassembled data, if possible"""
        more: Any
        next_header: Optional[int] = None
        if isinstance(ip, IPv4):
            more = IPv4.Flags[ip] & IPv4Flag.MF
            offset = IPv4.Fragment_Offset[ip] * 8
            data = IPv4.Payload.as_raw(ip)  # cannot always decode payload, as only fragment
            if offset == 0 and not more:
                return (None, data) if data else None
            key = IPv4.Source_IP[ip], IPv4.Destination_IP[ip], IPv4.Identification[ip]
        else:
            next_header = IPv6.Next_header[ip]
            if next_header != Header.Fragment:
                pay_type, pay = ip.get_payload()
                return pay_type, pay.encode()
            # data is fragmented
            frag = IPv6.Payload.as_frame(ip, frame_type=Fragment)
            assert isinstance(frag, Fragment)
            more = Fragment.M[frag]
            offset = Fragment.Fragment_offset[frag] * 8
            data = Fragment.Payload.as_raw(frag)
            key = IPv6.Source_address[ip], IPv6.Destination_address[ip], Fragment.Identification[frag]
            # reassembled payload type
            next_header = Fragment.Next_Header[frag]
        ent = self.queues.get(key)
        if not ent:
            ent = self.queues.setdefault(key, (RawDataQueue(), 0))
        queue, t_len = ent
        queue.push(data or Raw.empty, offset)
        if not more:
            # we now know how much data coming
            t_len = offset + (data.byte_length() if data else 0)
        if t_len and queue.head.fixed.byte_length() == t_len:
            # we have all data
            del self.queues[key]
            queue.close()
            return next_header, queue.head
        self.queues[key] = queue, t_len
        return None


class IPStackLayer(StackLayer):
    """IPx stack layer"""
    def __init__(self) -> None:
        super().__init__(layer_name="IPx")
        self.queues: Dict[Tuple[RawData, RawData, RawData], Tuple[RawDataQueue, int]] = {}

    def get_frame_type(self, state: StackState) -> Type[Frame]:
        return ip_frame_type(state.data)

    def receive(self, state: StackState) -> Iterable[StackState]:
        frame_type = self.get_frame_type(state)
        ip = frame_type(Frames.dissect(state.data))
        assert isinstance(ip, (IPv4, IPv6))
        pay_data = self.push(ip)
        if pay_data is None:
            return []
        pay_type, data = pay_data
        return [state.add(ip, pay_type, data)]

    def push(self, ip: IPx) -> Optional[Tuple[int, RawData]]:
        """Push IP frame, return payload type and reassembled data, if available"""
        more: Any
        if isinstance(ip, IPv4):
            more = IPv4.Flags[ip] & IPv4Flag.MF
            offset = IPv4.Fragment_Offset[ip] * 8
            pay_type = IPv4.Protocol[ip]
            data = IPv4.Payload.as_raw(ip) # cannot always decode payload, as only fragment
            if offset == 0 and not more:
                # not fragmented
                return pay_type, data or Raw.empty
            key = IPv4.Source_IP[ip], IPv4.Destination_IP[ip], IPv4.Identification[ip]
        else:
            pay_type = IPv6.Next_header[ip]
            if pay_type != Header.Fragment:
                # not fragmented
                pay_type, pay_frame = ip.get_payload()
                data = pay_frame.encode()
                return pay_type, data
            # data is fragmented
            frag = IPv6.Payload.as_frame(ip, frame_type=Fragment)
            assert isinstance(frag, Fragment)
            offset = Fragment.Fragment_offset[frag] * 8
            more = Fragment.M[frag]
            data = Fragment.Payload.as_raw(frag)
            pay_type = Fragment.Next_Header[frag]
            key = IPv6.Source_address[ip], IPv6.Destination_address[ip], Fragment.Identification[frag]
        ent = self.queues.get(key)
        if not ent:
            ent = self.queues.setdefault(key, (RawDataQueue(), 0))
        queue, t_len = ent
        queue.push(data or Raw.empty, offset)
        if not more:
            # we now know how much data coming
            t_len = offset + (data.byte_length() if data else 0)
        if t_len and queue.head.fixed.byte_length() == t_len:
            # we have all data
            del self.queues[key]
            queue.close()
            return pay_type, queue.head
        # must wait for more fragments
        self.queues[key] = queue, t_len
        return None

    def push_frame(self, ip: IPx) -> Optional[Frame]:
        """Push IP frame, get back frame, if possible"""
        r = self.push(ip)
        if r is None:
            return None
        field = IPv6.Payload if isinstance(ip, IPv6) else IPv4.Payload
        out = IPv6_Payloads.decode_payload(ip, field, payload_type = r[0], data=r[1])
        return out or RawFrame(Frames.dissect(r[1]))
