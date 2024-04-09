import argparse
import pathlib
import re
from typing import Any, Callable, Dict, Iterable, Optional, Type
import yaml

from framing.backends import RawFrame
from framing.base import Field, Frame
from framing.fields import RawField
from framing.frame_types.ethernet_frames import EthernetII
from framing.frame_types.ip_utilities import TCPStackLayer
from framing.frame_types.ip_utilities import DNSStackLayer
from framing.frame_types.ipv6_frames import IPx, IPStackLayer
from framing.frame_types.pcap_frames import PCAP_Payloads
from framing.frame_types.pcap_frames import PCAPStackLayer
from framing.frame_types.tls_frames import TLSHandshake
from framing.frame_types.ip_utilities import UDPStackLayer
from framing.frame_types.tls_frames import TLSRecordLayer
from framing.frames import Frames
from framing.raw_data import Raw
from framing.layer_stack import FrameStack, StackLayer, RawStackLayer, StackState


class PayloadFieldStackLayer(StackLayer):
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


class LayerBuilder:
    """Stack layer builder"""
    def __init__(self, short_name: str, new: Callable[[], StackLayer], sub: Dict[Any, 'LayerBuilder'] = None):
        self.short_name = short_name
        self.new = new
        self.sub = sub or {}
        assert short_name not in self.mappings, f"Duplicate layer name {short_name}"
        self.mappings[short_name] = self

    mappings: Dict[str, 'LayerBuilder'] = {}

    def build_layer(self, transport: Optional[Frame], spec: Dict[Any, Any]) -> StackLayer:
        """Build this layer"""
        return self.new().configure(spec)

    def build(self, stack: FrameStack, spec: Dict[Any, Any]):
        """Build stack layers by specification"""
        transport = stack.layer.frame_type

        p_regexp = re.compile(r"^_(\d+)$")  # '_'+number for decimal protocol type
        x_regexp = re.compile(r"^_x([0-9a-fA-F]+)$") # '_x' for hexadecimal protocol type
        for k, v in spec.items():
            # specify sub-protocol?
            if not isinstance(v, Dict):
                continue  # no configuration

            layer_builder = self.mappings.get(k)
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
                layer_builder = self.mappings.get(proto_name)
                if layer_builder is None:
                    raise ValueError(f'Unknown protocol "{proto_name}"')
                layer = layer_builder.build_layer(transport, v)
                next = stack.next[key] = FrameStack(layer)
                layer_builder.build(next, v)
            else:
                # key is protocol builder, find all mappings
                keys = []
                for sk, sub_builder in self.sub.items():
                    if sub_builder == layer_builder:
                        keys.append(sk)
                if not keys and layer_builder == StackBuilder.raw:
                    keys.append(None)  # raw builder is always in fashion
                if not keys:
                    raise ValueError(f'No mapping for "{k}" in "{self.short_name}"')
                for key in keys:
                    layer = layer_builder.build_layer(transport, v)
                    next = stack.next[key] = FrameStack(layer)
                    layer_builder.build(next, v)

        use_defaults = spec.get('defaults', True)
        if use_defaults and not stack.next:
            self.build_defaults(stack)


    def build_defaults(self, stack: FrameStack):
        # build default sub layers
        transport = stack.layer.frame_type
        for k, v in self.sub.items():
            layer = v.build_layer(transport, {})
            next = stack.next[k] = FrameStack(layer)
            v.build_defaults(next)
        stack.layer.show_unmapped = True


    def prepare_full_spec(self, spec: Dict[Any, Any]) -> Dict[Any, Any]:
        """Seek layers and construct full specification"""
        n_spec = {}
        for k, sub_builder in self.sub.items():
            name = sub_builder.short_name
            v = spec.get(name)
            if v is not None:
                n_spec[name] = v # build here

        unmapped = {k: v for k, v in spec.items() if k not in n_spec}
        if unmapped:
            # seek from lower layers
            for k, sub_builder in self.sub.items():
                name = sub_builder.short_name
                sub_spec = sub_builder.prepare_full_spec(unmapped)
                if sub_spec:
                    n_spec.update(sub_spec)
        if n_spec:
            n_spec = {self.short_name: n_spec}
        return n_spec


    def __repr__(self) -> str:
        return f"{self.short_name}"


class StackBuilder:
    """Singleton for stack layers"""

    dns = LayerBuilder('dns', lambda: DNSStackLayer())

    tls_handshake = LayerBuilder('tls-handshake', lambda: PayloadFieldStackLayer(TLSHandshake, TLSHandshake.HandshakeType, TLSHandshake.message))
    tls_record = LayerBuilder('tls-record', lambda: TLSRecordLayer(),
                              sub={22: tls_handshake})

    # basic IP protocols

    tcp = LayerBuilder('tcp', lambda: TCPStackLayer(),
                       sub={53: dns, 443: tls_record})
    udp = LayerBuilder('udp', lambda: UDPStackLayer(),
                       sub={53: dns})
    ip = LayerBuilder('ip', lambda: IPStackLayer(),
                      sub={6: tcp, 17: udp})
    eth = LayerBuilder('eth', lambda: PayloadFieldStackLayer(EthernetII, EthernetII.type, EthernetII.data),
                       sub={0x0800: ip, 0x86dd: ip})

    pcap = LayerBuilder('pcap', lambda: PCAPStackLayer(),
                        sub={1: eth})
    raw = LayerBuilder('raw', lambda: RawStackLayer())

    @classmethod
    def build_stack(cls, spec: Dict[Any, Any]) -> FrameStack:
        """Build stack from specification"""
        full_spec = cls.pcap.prepare_full_spec(spec)
        if len(full_spec) > 1:
            raise ValueError('Stack can have only one root layer, now: ' + ','.join(full_spec.keys()))
        for k, v in full_spec.items():
            layer_builder = LayerBuilder.mappings.get(k)
            if layer_builder is None:
                raise ValueError(f'Unknown protocol "{k}"')
            layer = layer_builder.build_layer(None, v)
            stack = FrameStack(layer)
            layer_builder.build(stack, v)
            break
        else:
            layer = cls.pcap.build_layer(None, {})
            stack = FrameStack(layer)
            cls.pcap.build_defaults(stack)
        return stack

def main():
    # Create the argument parser
    parser = argparse.ArgumentParser(description='PCAP printing tool')
    parser.add_argument('-s', '--stack', type=str, help='JSON/YAML-configured stack')
    parser.add_argument('read', type=str, action='append', help='Read PCAP file(s)')
    args = parser.parse_args()

    # construct the filtering
    filter_s = args.stack or ""
    filter_d = yaml.safe_load(filter_s) or {}
    stack = StackBuilder.build_stack(filter_d)

    # print extracted frames from files
    for file in args.read or []:
        f = pathlib.Path(file)
        data = Raw.file(f)
        try:
            st = StackState(data)
            for state in stack.receive(st):
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