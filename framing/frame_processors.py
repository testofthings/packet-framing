import typing
from typing import Generic, Iterator, Optional, Tuple, List

from framing.base import T
from framing.frame_types.ethernet_frames import EthernetII
from framing.frame_types.ip_utilities import TCPStackLayer
from framing.frame_types.ipv4_frames import IPv4
from framing.frame_types.ipv6_frames import IPReassembler, IPStackLayer, IPv6, IPx
from framing.frame_types.pcap_frames import PacketRecord
from framing.frame_types.tcp_frames import TCP, TCP_Stream_Id
from framing.frame_types.udp_frames import UDP
from framing.frames import Frames
from framing.raw_data import RawData

S = typing.TypeVar("S")


class MultiProcessor(typing.Generic[S, T]):
    def push_many(self, value: S) -> List[T]:
        raise NotImplementedError()


class Processor(MultiProcessor[S, T]):
    def push(self, value: S) -> Optional[T]:
        raise NotImplementedError()

    def push_many(self, value: S) -> List[T]:
        t = self.push(value)
        return [t] if t else []


class NoProcessor(typing.Generic[T], Processor[T, T]):
    def push(self, value: T) -> Optional[T]:
        return value


class PCAP2Ethernet(Processor[PacketRecord, T]):
    def __init__(self, sub: Optional[Processor[EthernetII, T]] = None):
        self.sub = NoProcessor() if sub is None else sub

    def push(self, value: PacketRecord) -> Optional[T]:
        fr = PacketRecord.Packet_Data.as_frame(value, frame_type=EthernetII)
        return self.sub.push(fr)


class Ethernet2IP(Processor[EthernetII, T]):
    def __init__(self, sub: Optional[Processor[IPv4, T]] = None):
        self.sub = NoProcessor() if sub is None else sub

    def push(self, value: EthernetII) -> Optional[T]:
        p = EthernetII.data.as_frame(value, default_frame=False)
        if isinstance(p, IPx):
            return self.sub.push(p)
        return None


class IP2UDP(Processor[IPx, T]):
    def __init__(self, sub: Optional[Processor[UDP, T]] = None):
        self.sub = NoProcessor() if sub is None else sub
        self.layer = IPStackLayer()

    def push(self, value: IPv4) -> Optional[T]:
        if isinstance(value, IPv4) or isinstance(value, IPv6):
            type_data = self.layer.push(value)
            if type_data is not None and type_data[0] == 0x11:
                frame = UDP(Frames.dissect(type_data[1]))
                return self.sub.push(frame), value
        return None

class IP2TCP(Processor[IPx, T]):
    """Extract TCP frames from IPx frames with IP reassembly"""
    def __init__(self, sub: Optional[Processor[Tuple[TCP, IPx], T]] = None):
        self.sub = NoProcessor() if sub is None else sub
        self.layer = IPStackLayer()

    def push(self, value: IPx) -> Optional[T]:
        if isinstance(value, IPv4) or isinstance(value, IPv6):
            type_data = self.layer.push(value)
            if type_data is not None and type_data[0] == 0x6:
                frame = TCP(Frames.dissect(type_data[1]))
                return self.sub.push(frame), value
        return None


class IP2TCPStream(Processor[IPx, Tuple[TCP_Stream_Id, RawData]]):
    """TCP stream processor, push IP frames, get back TCP stream data, if possible"""
    def __init__(self):
        self.layer = IPStackLayer()
        self.tcp_reassemble = TCPStackLayer()

    def push(self, value: IPx) -> Optional[Tuple[TCP_Stream_Id, RawData]]:
        if isinstance(value, IPv4) or isinstance(value, IPv6):
            type_data = self.layer.push(value)
            if type_data is not None and type_data[0] == 0x6:
                tcp = TCP(Frames.dissect(type_data[1]))
                key, data = self.tcp_reassemble.push((tcp, value))
                if data is not None:
                    return key, data
        return None


class ProcessorIterator(Generic[S, T], Iterator[T]):
    """Iterator which processes data from source iterator"""
    def __init__(self, source: Iterator[S], processor: Processor[S, T]):
        self.source = source
        self.processor = processor

    def __next__(self) -> T:
        while True:
            s = self.source.__next__()
            t = self.processor.push(s)
            if t:
                return t

    def __iter__(self) -> typing.Iterator[T]:
        return self
