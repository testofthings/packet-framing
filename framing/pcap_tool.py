import argparse
import pathlib
from typing import Any, Callable, Dict, Iterable, List, Optional, Type
import yaml

from framing.backends import RawFrame
from framing.base import Field, Frame
from framing.fields import RawField
from framing.frame_types.ethernet_frames import EthernetII
from framing.frame_types.ipv4_frames import IPv4
from framing.frame_types.ipv6_frames import IPv6
from framing.frame_types.pcap_frames import FileHeader, PCAP_Payloads, PCAPFile, PCAPRecordIterator, PacketRecord
from framing.frames import Frames
from framing.raw_data import Raw, RawData


class StackState:
    """Extractor output, frame and way to get payload data"""
    def __init__(self, data: RawData, lower: List[Frame] = None):
        self.data = data
        self.lower = [] if lower is None else lower

    def add(self, data: RawData, frame: Frame):
        """Add frame to the stack"""
        lower = self.lower.copy()
        lower.append(frame)
        return StackState(data, lower)

class FrameStackLayer:
    """Frame stack layer"""
    def __init__(self):
        self.next: Dict[Any, FrameStackLayer] = {}

    def input(self, state: StackState) -> Iterable[Frame]:
        """Input through the stack"""
        return [RawFrame(Frames.dissect(state.data))]

    def build(self, spec: Dict[Any, Any]):
        """Build this extractor recursively"""
        for k, v in spec.items():
            next = None
            if k == 'pcap':
                next = self.next[k] = PCAPStackLayer()
            if k == 'eth':
                next = self.next[1] = PayloadFieldStackLayer(EthernetII, EthernetII.type, EthernetII.data)
            # FIXME: Reassembly for payloads
            if k == 'ip4':
                next = self.next[0x0800] = PayloadFieldStackLayer(IPv4, IPv4.Protocol, IPv4.Payload)
            if k == 'ip6':
                next = self.next[0x86dd] = PayloadFieldStackLayer(IPv6, IPv6.Next_header, IPv6.Payload)
            if next and v and isinstance(v, Dict):
                next.build(v)


class FrameStack(FrameStackLayer):
    def input(self, state: StackState) -> Iterable[Frame]:
        if not self.next:
            return super().input(state)
        next = self.next.values().__iter__().__next__()
        return next.input(state)


class PCAPStackLayer(FrameStackLayer):
    """Extract PCAP records"""
    def input(self, state: StackState) -> Iterable[Frame]:
        file = PCAPFile(Frames.dissect(state.data))
        hdr = PCAPFile.File_Header[file]
        if not self.next:
            yield hdr
        next = self.next.get(FileHeader.LinkType[hdr])
        if not next and self.next:
            return []  # link type mismatch, no data to return
        for i, rec in enumerate(PCAPRecordIterator(file)):
            if not self.next:
                yield rec
            else:
                pay_data = PacketRecord.Packet_Data[rec]
                output = state.add(pay_data, rec)
                yield from next.input(output)

class PayloadFieldStackLayer(FrameStackLayer):
    """Extract frame from payload field"""
    def __init__(self, frame_type: Type[Frame], type_field: Field, payload_field: RawField):
        super().__init__()
        # force frame type initialization
        frame_type(Frames.compose())
        self.frame_type = frame_type
        self.type_field = type_field
        self.payload_field = payload_field

    def input(self, state: StackState) -> Iterable[Frame]:
        frame = self.frame_type(Frames.dissect(state.data))
        if not self.next:
             yield frame
        type_v = self.type_field[frame]
        next = self.next.get(type_v)
        if next is None:
            return []
        pay_raw = self.payload_field[frame]
        output = state.add(pay_raw, frame)
        out_d = next.input(output)
        yield from out_d

    def __repr__(self):
        return f"{self.frame_type.structure.structure_name}.{self.payload_field}"


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
    stack = FrameStack()
    stack.build(filter_d or {})

    # print extracted frames from files
    for file in args.read or []:
        f = pathlib.Path(file)
        data = Raw.file(f)
        try:
            for fr in stack.input(StackState(data)):
                print(f"{fr}")
        finally:
            data.close()

if __name__ == '__main__':
    main()