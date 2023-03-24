import typing
from typing import Optional, Tuple, List

from framing.base import T
from framing.frame_types.ethernet_frames import EthernetII
from framing.frame_types.ipv4_frames import IPv4
from framing.frame_types.ipv6_frames import IPReassembler
from framing.frame_types.pcap_frames import PacketRecord
from framing.frame_types.tcp_frames import TCP
from framing.frame_types.udp_frames import UDP
from framing.frames import Frames

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
        return self.sub.push(PacketRecord.Packet_Data.as_frame(value, frame_type=EthernetII))


class Ethernet2IP(Processor[EthernetII, T]):
    def __init__(self, sub: Optional[Processor[IPv4, T]] = None):
        self.sub = NoProcessor() if sub is None else sub

    def push(self, value: EthernetII) -> Optional[T]:
        p = EthernetII.data.as_frame(value, default_frame=False)
        if isinstance(p, IPv4):
            return self.sub.push(p)
        return None


class IP2UDP(Processor[IPv4, T]):
    def __init__(self, sub: Optional[Processor[UDP, T]] = None):
        self.sub = NoProcessor() if sub is None else sub
        self.assembler = IPReassembler()

    def push(self, value: IPv4) -> Optional[T]:
        if IPv4.Protocol[value] == 0x11:
            raw = self.assembler.push(value)
            if raw:
                return UDP(Frames.dissect(raw))
        return None


class IP2TCP(Processor[IPv4, T]):
    def __init__(self, sub: Optional[Processor[Tuple[TCP, IPv4], T]] = None):
        self.sub = NoProcessor() if sub is None else sub

    def push(self, value: IPv4) -> Optional[T]:
        if IPv4.Protocol[value] == 0x6:
            return self.sub.push(IPv4.Payload.as_frame(value, frame_type=TCP)), value
        return None
