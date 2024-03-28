import argparse
import pathlib
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Type
import yaml

from framing.backends import RawFrame
from framing.base import Field, Frame
from framing.data_queue import RawDataQueue
from framing.fields import RawField
from framing.frame_types.ethernet_frames import EthernetII
from framing.frame_types.ipv4_frames import IPv4, IPv4Flag
from framing.frame_types.ipv6_frames import Fragment, IPv6, IPx
from framing.frame_types.pcap_frames import FileHeader, PCAP_Payloads, PCAPFile, PCAPRecordIterator, PacketRecord
from framing.frames import Frames
from framing.raw_data import Raw, RawData


class StackState:
    """Extractor output, frame and way to get payload data"""
    def __init__(self, data: RawData, payload_type: Any = None, lower: List[Frame] = None):
        self.data = data
        self.payload_type = payload_type
        self.lower = [] if lower is None else lower

    def add(self, frame: Frame, payload_type: Any = None, data: RawData = Raw.empty):
        """Add frame to the stack"""
        lower = self.lower.copy()
        lower.append(frame)
        return StackState(data, payload_type, lower)

    def get_frame(self) -> Frame:
        """Get the top frame"""
        return self.lower[-1]

    def get_layer_names(self, omit_last = 0) -> str:
        """Get the string of layers names"""
        if len(self.lower) <= omit_last:
            return ""
        return ".".join([f"{f.structure.structure_name}" for f in self.lower[:-omit_last]])

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

    def receive(self, state: StackState) -> Iterable[StackState]:
        """Input through the stack"""
        frame = RawFrame(Frames.dissect(state.data))
        return [state.add(frame)]

    def __repr__(self) -> str:
        return f"{self.frame_type.structure.structure_name}"


class FrameStack:
    """Frame stack comprising layers"""
    def __init__(self, layer: FrameStackLayer = FrameStackLayer()):
        self.layer = layer
        self.next: Dict[Any, FrameStack] = {}  # higher layers keyed by payload types

    def receive(self, state: StackState) -> Iterable[StackState]:
        """Receive data through the stack"""
        if not self.next:
            # this is the top layer, no further processing
            out_frame = self.layer.frame_type(Frames.dissect(state.data))
            yield state.add(out_frame)
            return
        # this is intermediate layer, pass to higher layers
        for s in self.layer.receive(state):
            next = self.next.get(s.payload_type)
            if next is not None:
                yield from next.receive(s)

    def build(self, spec: Dict[Any, Any]):
        """Build this extractor recursively"""
        for k, v in spec.items():
            next = None
            if k == 'eth':
                next = self.next[1] = FrameStack(PayloadFieldStackLayer(EthernetII, EthernetII.type, EthernetII.data))
            if k == 'ip4':
                next = self.next[0x0800] = FrameStack(IPStackLayer(IPv4))
            if k == 'ip6':
                next = self.next[0x86dd] = FrameStack(IPStackLayer(IPv6))
            if next and v and isinstance(v, Dict):
                next.build(v)

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
            for s in stack.receive(StackState(data)):
                print(f"{s.get_layer_names(omit_last=1)}.{s.get_frame()}")
        finally:
            data.close()

if __name__ == '__main__':
    main()