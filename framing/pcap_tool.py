import argparse
import pathlib
import re
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple, Type
import yaml

from framing.backends import RawFrame
from framing.base import Field, Frame
from framing.data_queue import RawDataQueue
from framing.fields import RawField
from framing.frame_types.dns_frames import DNSMessage, DNSMessageTCP
from framing.frame_types.ethernet_frames import EthernetII
from framing.frame_types.ip_utilities import IPUtility
from framing.frame_types.ipv4_frames import IPv4, IPv4Flag
from framing.frame_types.ipv6_frames import Fragment, IPv6, IPx
from framing.frame_types.pcap_frames import FileHeader, PCAP_Payloads, PCAPFile, PCAPRecordIterator, PacketRecord
from framing.frame_types.tcp_frames import TCP, TCP_Null_Stream_Id, TCP_Stream_Id, TCPDataQueue, TCPFlag, flip_tcp_stream_id
from framing.frames import Frames
from framing.raw_data import Raw, RawData


class StackState:
    """Extractor output, frame and way to get payload data"""
    def __init__(self, data: RawData, payload_type: Any = None, frame: Optional[Frame] = None, lower: Optional['StackState'] = None):
        self.data = data
        self.payload_type = payload_type
        self.frame = frame
        self.lower = lower

    def add(self, frame: Frame, payload_type: Any = None, data: RawData = Raw.empty):
        """Add frame to the stack"""
        self.frame = frame  # update this frame
        return StackState(data, payload_type, lower=self)

    def get_frame(self) -> Frame:
        """Get the top frame, look for it"""
        return self.frame or (self.lower.get_frame() if self.lower else None)

    def get_layer_names(self) -> str:
        """Get the string of layers names"""
        ls = []
        s = self
        while s:
            lower = s.lower
            if s.frame:
                fs = s.frame.structure.structure_name
                p = s.payload_type
                if isinstance(p, Tuple) and len(p) == 4:
                    # Assuming source address+port and destination address+port
                    ks = f"{p[0].as_ip_address()}.{p[1]}, {p[2].as_ip_address()}.{p[3]}"
                    fs = f"{ks}={fs}"
                elif p is not None:
                    fs = f"{p}={fs}"
                ls.insert(0, fs)
            s = lower
        return " / ".join(ls)

    def __repr__(self) -> str:
        s = self.get_layer_names()
        if self.payload_type is not None:
            s = f"{s} " if s else ""
            s += f"paylod={self.payload_type}"
        s = f"{s}\n" if s else ""
        s += f"{self.data}"
        return s


class FrameStackLayer:
    """Frame stack layer"""
    def __init__(self, frame_type: Type[Frame] = RawFrame):
        self.frame_type = frame_type
        # force frame type initialization
        frame_type(Frames.compose())

    def get_frame_type(self, state: StackState) -> Frame:
        """Get frame type, may depend on transport layer"""
        return self.frame_type

    def receive(self, state: StackState) -> Iterable[StackState]:
        """Input through the stack"""
        frame = RawFrame(Frames.dissect(state.data))
        return [state.add(frame)]

    def configure(self, spec: Dict[Any, Any]) -> 'FrameStackLayer':
        """Configure this layer"""
        return self

    def __repr__(self) -> str:
        return f"{self.frame_type.structure.structure_name}"


class StackLayerBuilder:
    """Stack layer builder"""
    def __init__(self, mappings: Dict[Any, Callable[[], FrameStackLayer]] = {}):
        self.mappings = mappings

    def build(self, transport: Type[Frame]) -> Dict[Any, FrameStackLayer]:
        """Get the layer key to layer mapping"""
        return {k: v() for k, v in self.mappings.items()}


class FrameStack:
    """Frame stack comprising layers"""
    def __init__(self, layer: FrameStackLayer = FrameStackLayer()):
        self.layer = layer
        self.next: Dict[Any, FrameStack] = {}  # higher layers keyed by payload types

    def receive(self, state: StackState) -> Iterable[StackState]:
        """Receive data through the stack"""
        if not self.next:
            # this is the top layer, no further processing
            frame_type = self.layer.get_frame_type(state)
            out_frame = frame_type(Frames.dissect(state.data))
            yield state.add(out_frame)
            return
        # this is intermediate layer, pass to higher layers
        for s in self.layer.receive(state):
            if not s.data:
                continue  # do not pass empty data
            next = self.next.get(s.payload_type) or self.next.get(None)  # None key is fallback
            if next is not None:
                yield from next.receive(s)

    def build(self, spec: Dict[Any, Any]):
        """Build this extractor recursively"""
        transport = self.layer.frame_type

        p_regexp = re.compile(r"^_(\d+)$")  # '_'+number for decimal protocol type
        x_regexp = re.compile(r"^_x([0-9a-fA-F]+)$") # '_x' for hexadecimal protocol type
        for k, v in spec.items():
            # specify sub-protocol?
            if not isinstance(v, Dict):
                continue  # no configuration
            if k == "raw":
                # show raw data
                self.next[None] = FrameStack(FrameStackLayer())
                continue

            layer_builder = Stack_builder_map.get(k)
            if layer_builder is None:
                # not a protocol, maybe port number, payload type, etc. protocol key
                p_num = p_regexp.match(k) # integer key?
                key = int(p_num.group(1)) if p_num else None
                if key is None:
                    p_num = x_regexp.match(k)  # hex key?
                    key = int(p_num.group(1), 16) if p_num else None
                if key is None:
                    continue  # not key like for sub-protocol

                # payload protocol specified explictly
                proto_name = v.get('protocol') or v.get('p')
                if not proto_name:
                    raise ValueError('Missing protocol, use "protocol=" or "p="')
                layer_builder = Stack_builder_map.get(proto_name)
                if layer_builder is None:
                    raise ValueError(f'Unknown protocol "{proto_name}"')
                mappings = layer_builder.build(transport)
                if not mappings:
                    raise ValueError(f'Must specify layer key for "{proto_name}"')
                if len(mappings) != 1:
                    raise ValueError(f'"{proto_name}" is many protocols, it cannot be mapped to single layer key')
                layer_type = list(mappings.values())[0]
                layer = layer_type.configure(v)
                layer = layer.configure(v)
                s_layer = FrameStack(layer)
                s_layer.build(v)
                self.next[key] = s_layer
            else:
                # key is protocol builder, may map to several protocols
                mappings = layer_builder.build(transport)
                for key, layer_type in mappings.items():
                    layer = layer_type.configure(v)
                    s_layer = FrameStack(layer)
                    s_layer.build(v)
                    self.next[key] = s_layer

        # for k, v in spec.items():
        #     next = None
        #     if k == 'eth':
        #         next = self.next[1] = FrameStack(PayloadFieldStackLayer(EthernetII, EthernetII.type, EthernetII.data))
        #     if k == 'ip4':
        #         next = self.next[0x0800] = FrameStack(IPStackLayer(IPv4))
        #     if k == 'ip6':
        #         next = self.next[0x86dd] = FrameStack(IPStackLayer(IPv6))
        #     if k == 'tcp':
        #         next = self.next[6] = FrameStack(TCPStackLayer())
        #     if k == 'dns':
        #         next = self.next[53] = FrameStack(FrameStackLayer(DNSMessageTCP))
        #     if k == 'raw':
        #         next = self.next[None] = FrameStack(FrameStackLayer())  # any data
        #     if next and v and isinstance(v, Dict):
        #         next.build(v)

    def __repr__(self) -> str:
        s = f"{self.layer}"
        for k, v in self.next.items():
            s += f"\n  {k}: {v.layer}"
        return s


class PCAPStackLayer(FrameStackLayer):
    """PCAP stack layer"""
    def __init__(self):
        super().__init__(PCAPFile)

    def receive(self, state: StackState) -> Iterable[StackState]:
        file = PCAPFile(Frames.dissect(state.data))
        hdr = PCAPFile.File_Header[file]
        pay_type = FileHeader.LinkType[hdr]
        state = state.add(file)
        for i, rec in enumerate(PCAPRecordIterator(file)):
            pay_data = PacketRecord.Packet_Data[rec]
            n_state = state.add(rec, pay_type, pay_data)
            yield n_state


class PayloadFieldStackLayer(FrameStackLayer):
    """Generic stack layer"""
    def __init__(self, frame_type: Type[Frame], type_field: Field, payload_field: RawField):
        super().__init__(frame_type)
        self.type_field = type_field
        self.payload_field = payload_field

    def receive(self, state: StackState) -> Iterable[StackState]:
        frame = self.frame_type(Frames.dissect(state.data))
        pay_type = self.type_field[frame]
        pay_data = self.payload_field[frame]
        s_state = state.add(frame, pay_type, pay_data)
        return [s_state]

    def __repr__(self):
        return f"{self.frame_type.structure.structure_name}.{self.payload_field}"


class IPStackLayer(FrameStackLayer):
    """IPx stack layer"""
    def __init__(self, frame_type: IPx):
        super().__init__(frame_type)
        assert frame_type in {IPv4, IPv6}, f"Expected IPx, got {frame_type}"
        self.queues: Dict[Tuple[RawData, RawData, RawData], Tuple[RawDataQueue, int]] = {}

    def receive_raw(self, data: RawData) -> Iterable[Tuple[int, RawData]]:
        """Receive raw IP data and yield payload type and raw data"""
        for s in self.receive(StackState(data)):
            yield s.payload_type, s.data

    def receive(self, state: StackState) -> Iterable[StackState]:
        ip = self.frame_type(Frames.dissect(state.data))
        if isinstance(ip, IPv4):
            more = IPv4.Flags[ip] & IPv4Flag.MF
            offset = IPv4.Fragment_Offset[ip] * 8
            pay_type = IPv4.Protocol[ip]
            data = IPv4.Payload.as_raw(ip)  # cannot always decode payload, as only fragment
            if offset == 0 and not more:
                # not fragmented
                return [state.add(ip, pay_type, data)]
            key = IPv4.Source_IP[ip], IPv4.Destination_IP[ip], IPv4.Identification[ip]
        else:
            pay_type = IPv6.Next_header[ip]
            if pay_type != 0x2c:
                # not fragmented
                data = IPv6.Payload.as_raw(ip)
                return [state.add(ip, pay_type, data)]
            # data is fragmented
            frag = IPv6.Payload.as_frame(ip, frame_type=Fragment)
            assert isinstance(frag, Fragment)
            more = Fragment.M[frag]
            offset = Fragment.Fragment_offset[frag]
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
            return [state.add(ip, pay_type, queue.head)]
        # must wait for more fragments
        self.queues[key] = queue, t_len
        return []


class TCPStackLayer(FrameStackLayer):
    def __init__(self, full_streams=False):
        super().__init__(TCP)
        self.queues: Dict[TCP_Stream_Id, TCPDataQueue] = {}
        self.to_server: Set[TCP_Stream_Id] = set()  # streams towards server
        self.full_stream = full_streams

    def receive_queue(self, packets: Optional[Tuple[TCP, IPx]]) -> Tuple[TCP_Stream_Id, Optional[RawDataQueue]]:
        """Push TCP frame, get back raw data queue"""
        if packets is None:
            return TCP_Null_Stream_Id, None
        tcp, ip = packets
        flags = TCP.Flags[tcp]
        start = flags & TCPFlag.SYN

        sd = IPUtility.get_source_destination(ip)
        key = sd[0], TCP.Source_port[tcp], sd[1], TCP.Destination_port[tcp]
        if start:
            queue = TCPDataQueue(tcp)
            self.queues[key] = queue
            r_key = flip_tcp_stream_id(key)
            if r_key not in self.to_server:
                self.to_server.add(key)  # assume first packet is towards server
        else:
            queue = self.queues.get(key)
            if not queue:
                return key, None  # no start seen

        if queue.is_closed():
            del self.queues[key]  # remove closed
        queue.push_frame(tcp)
        return key, queue

    def receive(self, state: StackState) -> Iterable[StackState]:
        """Push TCP frame, get back raw data queue"""
        tcp = TCP(Frames.dissect(state.data))
        ip = state.get_frame()
        assert isinstance(ip, IPx), f"Expected IPx as TCP transport, got {type(ip)}"
        key, queue = self.receive_queue((tcp, ip))
        # use server port to identify payload type
        server_port = key[3] if key in self.to_server else key[1]
        if not queue:
            return []  # no data available
        if queue.is_closed():
            data = queue.pull_all()
            return [state.add(tcp, server_port, data)]
        if self.full_stream:
            return []
        data = queue.pull_all()
        return [state.add(tcp, server_port, data)]


class DNSStackLayer(FrameStackLayer):
    def __init__(self):
        super().__init__(DNSMessage)

    def get_frame_type(self, state: StackState) -> Frame:
        if state.lower and isinstance(state.lower.frame, TCP):
            return DNSMessageTCP
        return DNSMessage


# Stack layer builders by layer keys (port numbers, etc.)
Stack_builder_map: Dict[str, Callable[[], StackLayerBuilder]] = {
    'eth': StackLayerBuilder({1: lambda: PayloadFieldStackLayer(EthernetII, EthernetII.type, EthernetII.data) }),
    'ip4': StackLayerBuilder({0x0800: lambda: IPStackLayer(IPv4)}),
    'ip6': StackLayerBuilder({0x86dd: lambda: IPStackLayer(IPv6)}),
    'ip': StackLayerBuilder({0x0800: lambda: IPStackLayer(IPv4), 0x86dd: lambda: IPStackLayer(IPv6)}),
    'tcp': StackLayerBuilder({6: lambda: TCPStackLayer()}),
    'dns': StackLayerBuilder({53: lambda: DNSStackLayer()}),
}


def main():
    # Create the argument parser
    parser = argparse.ArgumentParser(description='PCAP printing tool')
    parser.add_argument('-f', '--filter', type=str, help='YAML-formatted packet filter')
    parser.add_argument('read', type=str, action='append', help='Read PCAP file(s)')
    args = parser.parse_args()

    # construct the filtering
    filter_s = args.filter or ""
    # add space after colon to faciliate more compact command-line notation
    filter_s = filter_s.replace(':{', ': {')
    filter_d = yaml.safe_load(filter_s)
    stack = FrameStack(layer=PCAPStackLayer())
    stack.build(filter_d or {})

    # print extracted frames from files
    for file in args.read or []:
        f = pathlib.Path(file)
        data = Raw.file(f)
        try:
            for state in stack.receive(StackState(data)):
                s = f"{state.get_frame()}"
                # drop first line of frame dump, it contains extra frame name
                first_line_len = s.find('\n')
                if first_line_len > 0 and first_line_len < len(s):
                    s = s[first_line_len + 1:]
                print(f"{state.get_layer_names()}\n{s}")
        finally:
            data.close()

if __name__ == '__main__':
    main()