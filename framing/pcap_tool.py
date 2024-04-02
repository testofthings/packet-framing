import argparse
import pathlib
from typing import Callable, Dict, Iterable, Optional, Type
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
from framing.layer_stack import FrameStack, FrameStackLayer, StackLayerBuilder, StackState


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


# Stack layer builders by layer keys (port numbers, etc.)
Stack_builder_map: Dict[str, Callable[[], StackLayerBuilder]] = {
    'eth': StackLayerBuilder({1: lambda: PayloadFieldStackLayer(EthernetII, EthernetII.type, EthernetII.data) }),
    'ip': StackLayerBuilder({0x0800: lambda: IPStackLayer(), 0x86dd: lambda: IPStackLayer()}),
    'udp': StackLayerBuilder({17: lambda: UDPStackLayer()}),
    'tcp': StackLayerBuilder({6: lambda: TCPStackLayer()}),
    'dns': StackLayerBuilder({53: lambda: DNSStackLayer()}),
    'tls-record': StackLayerBuilder({443: lambda: TLSRecordLayer()}),
    'tls-handshake': StackLayerBuilder({22: lambda: PayloadFieldStackLayer(TLSHandshake, TLSHandshake.HandshakeType, TLSHandshake.message)}),
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
    stack.build(filter_d or {}, Stack_builder_map)

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