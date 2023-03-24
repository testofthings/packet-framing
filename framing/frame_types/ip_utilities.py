from typing import Dict, Tuple, Optional

from framing.data_queue import RawDataQueue
from framing.frame_types.ipv4_frames import IPv4
from framing.frame_types.ipv6_frames import IPx, IPv6
from framing.frame_types.tcp_frames import TCP_Stream_Id, TCP, TCPFlag, TCPDataQueue
from framing.raw_data import RawData


# Utility functions
class IPUtility:
    @classmethod
    def get_source_destination(cls, ip: IPx) -> Tuple[RawData, RawData]:
        if isinstance(ip, IPv4):
            return IPv4.Source_IP[ip], IPv4.Destination_IP[ip]
        return IPv6.Source_address[ip], IPv6.Destination_address[ip]


class TCPReassembler:
    """TCP reassembler"""
    def __init__(self, full_streams=False):
        self.queues: Dict[TCP_Stream_Id, TCPDataQueue] = {}
        self.full_stream = full_streams

    def push(self, packets: Tuple[TCP, IPx]) -> Optional[RawData]:
        """Push TCP frame, get back raw data, if possible"""
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
                return None  # no start seen

        queue.push_frame(tcp)
        if queue.is_closed():
            del self.queues[key]
            return queue.pull_all()
        if self.full_stream:
            return None
        data = queue.pull_all()
        return data
