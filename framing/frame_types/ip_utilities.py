from typing import Dict, Iterator, Self, Tuple, Optional

from framing.data_queue import RawDataQueue
from framing.frame_types.ipv4_frames import IPv4
from framing.frame_types.ipv6_frames import IPx, IPv6
from framing.frame_types.tcp_frames import TCP_Null_Stream_Id, TCP_Stream_Id, TCP, TCPFlag, TCPDataQueue
from framing.raw_data import RawData


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
        if queue.is_closed():
            return key, queue.pull_all()
        if self.full_stream:
            return key, None
        data = queue.pull_all()
        return key, data

