from typing import Dict, Iterator, Self, Tuple, Optional

from framing.data_queue import RawDataQueue
from framing.frame_processors import Processor
from framing.frame_types.ipv4_frames import IPv4
from framing.frame_types.ipv6_frames import IPReassembler, IPx, IPv6
from framing.frame_types.tcp_frames import TCP_Null_Stream_Id, TCP_Stream_Id, TCP, TCPFlag, TCPDataQueue
from framing.raw_data import Raw, RawData


# Utility functions
class IPUtility:
    @classmethod
    def get_source_destination(cls, ip: IPx) -> Tuple[RawData, RawData]:
        if isinstance(ip, IPv4):
            return IPv4.Source_IP[ip], IPv4.Destination_IP[ip]
        return IPv6.Source_address[ip], IPv6.Destination_address[ip]


class TCPReassembler:
    """TCP reassembler, push TCP frames, get raw data back"""
    def __init__(self, full_streams=False):
        self.queues: Dict[TCP_Stream_Id, TCPDataQueue] = {}
        self.full_stream = full_streams

    def push(self, packets: Tuple[TCP, IPx]) -> Tuple[TCP_Stream_Id, Optional[RawData]]:
        """Push TCP frame, get back raw data, if possible"""
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
        else:
            queue = self.queues.get(key)
            if not queue:
                return key, None  # no start seen

        queue.push_frame(tcp)
        if queue.is_closed():
            del self.queues[key]
            return key, queue.pull_all()
        if self.full_stream:
            return key, None
        data = queue.pull_all()
        return key, data


class IP2TCPStream(Processor[IPx, Tuple[TCP_Stream_Id, RawData]]):
    """TCP stream processor, push IP frames, get back TCP stream data, if possible"""
    def __init__(self, full_streams=False):
        self.reassemble = IPReassembler()
        self.tcp_reassemble = TCPReassembler(full_streams)

    def push(self, value: IPx) -> Optional[Tuple[TCP_Stream_Id, RawData]]:
        if isinstance(value, IPv4):
            if IPv4.Protocol[value] != 0x6:
                return None
            tcp = self.reassemble.push_frame(value)
        elif isinstance(value, IPv6):
            if IPv6.Next_header[value] != 0x6:
                return None
            tcp = self.reassemble.push_frame(value)
        else:
            return None
        if not tcp:
            return None
        key, data = self.tcp_reassemble.push((tcp, value))
        if data is None:
            return None
        return key, data


class TCPDataTable:
    """Store TCP data by stream id"""
    def __init__(self) -> None:
        self.data: Dict[TCP_Stream_Id, RawData] = {}

    def push(self, data: Optional[Tuple[TCP_Stream_Id, RawData]]) -> Optional[Tuple[TCP_Stream_Id, RawData]]:
        """Push pair of stream key and data"""
        if data is None:
            return None
        key, d = data
        old = self.data.get(key, Raw.empty)
        self.data[key] = Raw.concat(old, d)
        return data

    def push_all(self, streams: Iterator[Tuple[TCP_Stream_Id, RawData]]) -> Self:
        """Push all stream data"""
        for data in streams:
            self.push(data)
        return self
