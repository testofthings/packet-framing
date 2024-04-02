import argparse
import pathlib
from typing import Callable, Dict, Iterable, Optional, Set, Tuple, Type
import yaml

from framing.backends import RawFrame
from framing.base import Field, Frame
from framing.data_queue import RawDataQueue
from framing.fields import RawField
from framing.frame_types.dns_frames import DNSMessage, DNSMessageTCP
from framing.frame_types.ethernet_frames import EthernetII
from framing.frame_types.ip_utilities import IPUtility
from framing.frame_types.ip_utilities import TCPStackLayer
from framing.frame_types.ipv6_frames import IPx, IPStackLayer
from framing.frame_types.pcap_frames import FileHeader, PCAP_Payloads, PCAPFile, PCAPRecordIterator, PacketRecord
from framing.frame_types.tcp_frames import TCP
from framing.frame_types.tls_frames import TLSHandshake, TLSRecord
from framing.frame_types.udp_frames import UDP
from framing.frames import Frames
from framing.raw_data import Raw, RawData
from framing.layer_stack import FrameStack, FrameStackLayer, StackLayerBuilder, StackState


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


class UDPStackLayer(FrameStackLayer):
    def __init__(self):
        super().__init__(UDP)
        self.to_server: Set[Tuple[RawData, int]] = set()  # packets towards server

    def receive(self, state: StackState) -> Iterable[StackState]:
        udp = UDP(Frames.dissect(state.data))
        ip = state.get_frame()
        assert isinstance(ip, IPx), f"Expected IPx as UDP transport, got {type(ip)}"
        s_host, d_host = IPUtility.get_source_destination(ip)
        to_key = d_host, UDP.Destination_port[udp]
        if to_key in self.to_server:
            return [state.add(udp, to_key[1], UDP.Data[udp])]  # client to server
        from_key = s_host, UDP.Source_port[udp]
        if from_key in self.to_server:
            return [state.add(udp, from_key[1], UDP.Data[udp])]  # server to client
        # assume first packet is towards server
        self.to_server.add(to_key)
        return [state.add(udp, to_key[1], UDP.Data[udp])]


class DNSStackLayer(FrameStackLayer):
    def __init__(self):
        super().__init__(DNSMessage)

    def get_frame_type(self, state: StackState) -> Frame:
        if state.lower and isinstance(state.lower.frame, TCP):
            return DNSMessageTCP
        return DNSMessage


class TLSRecordLayer(FrameStackLayer):
    def __init__(self):
        super().__init__(TLSRecord)
        self.queue = RawDataQueue()

    def receive(self, state: StackState) -> Iterable[StackState]:
        record = TLSRecord(Frames.dissect(state.data))
        self.queue.push(TLSRecord.fragment[record])
        if not self.queue:
            return []
        data = self.queue.pull_all()
        return [state.add(record, TLSRecord.ContentType[record], data)]


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