from typing import Any, Dict, Iterable, Iterator, Self, Set, Tuple, Optional

from framing.base import Frame
from framing.data_queue import RawDataQueue
from framing.frame_types.dns_frames import DNSMessage, DNSMessageTCP
from framing.frame_types.ipv4_frames import IPv4
from framing.frame_types.ipv6_frames import IPx, IPv6
from framing.frame_types.tcp_frames import TCP_Null_Stream_Id, TCP_Stream_Id, TCP, TCPFlag, TCPDataQueue, flip_tcp_stream_id
from framing.frame_types.udp_frames import UDP
from framing.frames import Frames
from framing.layer_stack import StackLayer, StackState
from framing.raw_data import RawData


# Utility functions
class IPUtility:
    @classmethod
    def get_source_destination(cls, ip: IPx) -> Tuple[RawData, RawData]:
        if isinstance(ip, IPv4):
            return IPv4.Source_IP[ip], IPv4.Destination_IP[ip]
        return IPv6.Source_address[ip], IPv6.Destination_address[ip]


class TCPStackLayer(StackLayer):
    def __init__(self):
        super().__init__(TCP)
        self.streaming = True
        self.queues: Dict[TCP_Stream_Id, TCPDataQueue] = {}
        self.to_server: Set[TCP_Stream_Id] = set()  # streams towards server

    def receive(self, state: StackState) -> Iterable[StackState]:
        tcp = TCP(Frames.dissect(state.data))
        ip = state.get_frame()
        assert isinstance(ip, IPx), f"Expected IPx as TCP transport, got {type(ip)}"
        key, queue = self.push_queue((tcp, ip))
        # use server port to identify payload type
        server_port = key[3] if key in self.to_server else key[1]
        if not queue:
            return []  # no data available
        data = queue.head.fixed
        # With stream ID, stream can produce more data
        return [state.add(tcp, server_port, data, stream_id=key)]

    def commit_read(self, stream_id: Any, byte_length: int):
        queue = self.queues.get(stream_id)
        assert queue, f"Unexpected TCP stream id {stream_id}"
        queue.forward(byte_length)

    def push_queue(self, packets: Optional[Tuple[TCP, IPx]]) -> Tuple[TCP_Stream_Id, Optional[RawDataQueue]]:
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

    def push(self, packets: Optional[Tuple[TCP, IPx]]) -> Tuple[TCP_Stream_Id, Optional[RawData]]:
        """Push TCP frame, get back raw data, if more available"""
        key, queue = self.push_queue(packets)
        if not queue:
            return key, None  # no queue
        data = queue.pull_all()
        return key, data


class UDPStackLayer(StackLayer):
    """UDP stack layer"""
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


class DNSStackLayer(StackLayer):
    def __init__(self):
        super().__init__(DNSMessage)

    def get_frame_type(self, state: StackState) -> Frame:
        if state.lower and isinstance(state.lower.frame, TCP):
            return DNSMessageTCP
        return DNSMessage
