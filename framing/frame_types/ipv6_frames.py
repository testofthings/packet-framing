from types import UnionType
from typing import Iterable, Tuple, Dict, Optional, Union

from framing.base import Frame, LayerMapping
from framing.data_queue import RawDataQueue
from framing.fields import Structure, ValueOf
from framing.frame_types.ipv4_frames import IP_Payloads, IPv4, IPv4Flag
from framing.frames import Frames
from framing.layer_stack import StackLayer, StackState
from framing.raw_data import IPAddress, RawData


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

    Payload = structure.raw().length_by(ValueOf(Payload_length))

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


# Either IPv4 or IPv6
IPx = Union[IPv4 | IPv6]


IPv6_Payloads = LayerMapping(base=IP_Payloads).many_by({
    IPv6.Payload: IPv6.Next_header,
    Fragment.Payload: Fragment.Next_Header,
}, {
    0x2c: Fragment,
    0x3a: ICMPv6,
})


class IPReassembler:
    """IPx reassembler"""
    def __init__(self):
        self.queues: Dict[Tuple[RawData, RawData, RawData], Tuple[RawDataQueue, int]] = {}

    def push_frame(self, ip: IPx) -> Optional[Frame]:
        """Push IP frame, get back frame, if possible"""
        r = self.push(ip)
        if r is None:
            return None
        field = IPv6.Payload if isinstance(ip,IPv6) else IPv4.Payload
        out = IPv6_Payloads.decode_payload(ip, field, data=r)
        return out

    def push(self, ip: IPx) -> Optional[RawData]:
        """Push IP frame, get back reassembled data, if possible"""
        if isinstance(ip, IPv4):
            more = IPv4.Flags[ip] & IPv4Flag.MF
            offset = IPv4.Fragment_Offset[ip] * 8
            data = IPv4.Payload.as_raw(ip)  # cannot always decode payload, as only fragment
            if offset == 0 and not more:
                return data
            key = IPv4.Source_IP[ip], IPv4.Destination_IP[ip], IPv4.Identification[ip]
        else:
            if IPv6.Next_header[ip] != 0x2c:
                return IPv6.Payload.as_raw(ip)
            # data is fragmented
            frag = IPv6.Payload.as_frame(ip, frame_type=Fragment)
            assert isinstance(frag, Fragment)
            more = Fragment.M[frag]
            offset = Fragment.Fragment_offset[frag] * 8
            data = Fragment.Payload.as_raw(frag)
            key = IPv6.Source_address[ip], IPv6.Destination_address[ip], Fragment.Identification[frag]
        ent = self.queues.get(key)
        if not ent:
            ent = self.queues.setdefault(key, (RawDataQueue(), 0))
        queue, t_len = ent
        queue.push(data, offset)
        if not more:
            # we now know how much data coming
            t_len = offset + data.byte_length()
        if t_len and queue.head.fixed.byte_length() == t_len:
            # we have all data
            del self.queues[key]
            queue.close()
            return queue.head
        self.queues[key] = queue, t_len
        return None


class IPStackLayer(StackLayer):
    """IPx stack layer"""
    def __init__(self):
        super().__init__(IPv4)
        self.queues: Dict[Tuple[RawData, RawData, RawData], Tuple[RawDataQueue, int]] = {}

    def get_frame_type(self, state: StackState) -> Frame:
        version = state.data.octet(0) >> 4
        if version == 4:
            return IPv4
        if version == 6:
            return IPv6
        raise ValueError(f"Unknown IP version {version}")

    def receive(self, state: StackState) -> Iterable[StackState]:
        frame_type = self.get_frame_type(state)
        ip = frame_type(Frames.dissect(state.data))
        pay_data = self.push(ip)
        if pay_data is None:
            return []
        pay_type, data = pay_data
        return [state.add(ip, pay_type, data)]

    def push(self, ip: IPx) -> Optional[Tuple[int, RawData]]:
        """Push IP frame, return payload type and reassembled data, if available"""
        if isinstance(ip, IPv4):
            more = IPv4.Flags[ip] & IPv4Flag.MF
            offset = IPv4.Fragment_Offset[ip] * 8
            pay_type = IPv4.Protocol[ip]
            data = IPv4.Payload.as_raw(ip)  # cannot always decode payload, as only fragment
            if offset == 0 and not more:
                # not fragmented
                return pay_type, data
            key = IPv4.Source_IP[ip], IPv4.Destination_IP[ip], IPv4.Identification[ip]
        else:
            pay_type = IPv6.Next_header[ip]
            if pay_type != 0x2c:
                # not fragmented
                data = IPv6.Payload.as_raw(ip)
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
        queue.push(data, offset)
        if not more:
            # we now know how much data coming
            t_len = offset + data.byte_length()
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
        field = IPv6.Payload if isinstance(ip,IPv6) else IPv4.Payload
        out = IPv6_Payloads.decode_payload(ip, field, data=r[1])
        return out
