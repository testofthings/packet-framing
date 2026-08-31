"""Command-line tool for PCAP dissection"""

import argparse
import pathlib
import re
from typing import Any, Callable, Dict, Iterable, Self, Type
import yaml

from framing.base import AnyField, Frame
from framing.frame_types.ethernet_frames import EthernetII
from framing.frame_types.ip_utilities import TCPStackLayer
from framing.frame_types.ip_utilities import DNSStackLayer
from framing.frame_types.ipv6_frames import IPStackLayer
from framing.frame_types.llc_frames import LLC
from framing.frame_types.capture_files import CaptureStackLayer
from framing.frame_types.pcap_frames import LINKTYPE_ETHERNET, LINKTYPE_IEEE802_11, LINKTYPE_RAW
from framing.frame_types.tls_frames import TLSHandshake
from framing.frame_types.ip_utilities import UDPStackLayer
from framing.frame_types.tls_frames import TLSRecordLayer
from framing.frame_types.wifi_frames import WiFiStackLayer, DATA, QOS_DATA
from framing.frames import Frames
from framing.raw_data import Raw
from framing.layer_stack import FrameStack, StackLayer, RawStackLayer, StackState


class PayloadFieldStackLayer(StackLayer):
    """Stack layer with data in payload field"""
    def __init__(self, frame_type: Type[Frame], type_field: AnyField, payload_field: AnyField):
        super().__init__(frame_type)
        self.type_field = type_field
        self.payload_field = payload_field

    def receive(self, state: StackState) -> Iterable[StackState]:
        # TODO: This code is never tested for!
        frame = self.frame_type(Frames.dissect(state.data))
        pay_type = self.type_field[frame]
        pay_data = self.payload_field.as_raw(frame) or Raw.empty
        s_state = state.add(frame, pay_type, pay_data)
        return [s_state]

    def __repr__(self) -> str:
        return f"{self.frame_type.__name__}.{self.payload_field}"


class LayerBuilder:
    """Stack layer builder"""
    def __init__(self, short_name: str, new: Callable[[], StackLayer], sub: Dict[Any, 'LayerBuilder'] | None = None):
        self.short_name = short_name
        self.new = new
        self.sub = sub or {}
        assert short_name not in self.mappings, f"Duplicate layer name {short_name}"
        self.mappings[short_name] = self

    mappings: Dict[str, 'LayerBuilder'] = {}

    def build_layer(self, spec: Dict[Any, Any]) -> StackLayer:
        """Build this layer"""
        return self.new().configure(spec)

    def build(self, stack: FrameStack, spec: Dict[Any, Any]) -> Self:
        """Build stack layers by specification"""
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
                layer = layer_builder.build_layer(v)
                next_item = stack.next[key] = FrameStack(layer)
                layer_builder.build(next_item, v)
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
                    layer = layer_builder.build_layer(v)
                    next_value = stack.next[key] = FrameStack(layer)
                    layer_builder.build(next_value, v)

        use_defaults = spec.get('defaults', True)
        if use_defaults and not stack.next:
            self.build_defaults(stack)
        return self


    def build_defaults(self, stack: FrameStack) -> Self:
        """Build default sub layers"""
        for k, v in self.sub.items():
            layer = v.build_layer({})
            next_item = stack.next[k] = FrameStack(layer)
            v.build_defaults(next_item)
        stack.layer.show_unmapped = True
        return self


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

    dns = LayerBuilder('dns', DNSStackLayer)

    tls_handshake = LayerBuilder('tls-handshake',
                                 lambda: PayloadFieldStackLayer(TLSHandshake,
                                                                TLSHandshake.HandshakeType,
                                                                TLSHandshake.message))
    tls_record = LayerBuilder('tls-record', TLSRecordLayer,
                              sub={22: tls_handshake})

    # basic IP protocols

    tcp = LayerBuilder('tcp', TCPStackLayer,
                       sub={53: dns, 443: tls_record})
    udp = LayerBuilder('udp', UDPStackLayer,
                       sub={53: dns})
    ip = LayerBuilder('ip', IPStackLayer,
                      sub={6: tcp, 17: udp})
    eth = LayerBuilder('eth', lambda: PayloadFieldStackLayer(EthernetII, EthernetII.type, EthernetII.data),
                       sub={0x0800: ip, 0x86dd: ip})

    # 802.11 with LLC/SNAP encapsulation

    llc = LayerBuilder('llc', lambda: PayloadFieldStackLayer(LLC, LLC.Type, LLC.Data),
                       sub={0x0800: ip, 0x86dd: ip})
    wifi = LayerBuilder('wifi', WiFiStackLayer,
                        sub={DATA: llc, QOS_DATA: llc})

    pcap = LayerBuilder('pcap', CaptureStackLayer,
                        sub={LINKTYPE_ETHERNET: eth, LINKTYPE_IEEE802_11: wifi, LINKTYPE_RAW: ip})
    raw = LayerBuilder('raw', RawStackLayer)

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
            layer = layer_builder.build_layer(v)
            stack = FrameStack(layer)
            layer_builder.build(stack, v)
            break
        else:
            layer = cls.pcap.build_layer({})
            stack = FrameStack(layer)
            cls.pcap.build_defaults(stack)
        return stack

def main() -> None:
    """Entry point to the command"""
    # Create the argument parser
    parser = argparse.ArgumentParser(description='PCAP printing tool')
    parser.add_argument('-s', '--stack', type=str, help='JSON/YAML-configured stack')
    parser.add_argument('read_file', type=str, action='append', help='Read PCAP file(s)')
    args = parser.parse_args()

    # construct the filtering
    filter_s = args.stack or ""
    filter_d = yaml.safe_load(filter_s) or {}
    stack = StackBuilder.build_stack(filter_d)

    # print extracted frames from files
    for file in args.read_file or []:
        f = pathlib.Path(file)
        data = Raw.file(f)
        try:
            st = StackState(data)
            for state in stack.receive(st):
                s = f"{state.get_frame()}"
                # drop first line of frame dump, it contains extra frame name
                first_line_len = s.find('\n')
                if 0 < first_line_len < len(s):
                    s = s[first_line_len + 1:]
                print(f"{state.get_layer_names()}\n{s}")
        except ValueError as e:
            raise SystemExit(f"{f}: {e}") from e  # e.g. unsupported file format
        finally:
            data.close()

if __name__ == '__main__':
    main()
