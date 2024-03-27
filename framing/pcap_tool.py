import argparse
import pathlib
from typing import Any, Callable, Dict, Iterable, List, Optional, Type
import yaml

from framing.backends import RawFrame
from framing.base import Field, Frame
from framing.frame_types.ethernet_frames import EthernetII
from framing.frame_types.pcap_frames import PCAPFile, PCAPRecordIterator, PacketRecord
from framing.frames import Frames
from framing.raw_data import Raw, RawData


class FrameOutput:
    """Extractor output, frame and way to get payload data"""
    def __init__(self, frame: Frame, payload: Field = None):
        self.frame = frame
        self.payload = payload


class FrameExtractor:
    """Extract frames from raw data using a specification"""
    def __init__(self, spec: Dict[Any, Any]):
        self.process: Callable[[RawData], Iterable[Frame]] = self._no_processing
        self.next: Optional[FrameExtractor] = None
        self._build(spec)

    def _build(self, spec: Dict[Any, Any]):
        """Build this extractor recursively"""
        for k, v in spec.items():
            if k == 'pcap':
                self.process = self._extract_pcap_records
            if k == 'eth':
                self.process = self._extract_ethernet_frames
            if isinstance(v, Dict) and v:
                self.next = FrameExtractor(v)

    def _no_processing(self, data: RawData) -> Iterable[FrameOutput]:
        return [FrameOutput(RawFrame(Frames.dissect(data)))]

    def _extract_pcap_records(self, data: RawData) -> Iterable[FrameOutput]:
        """Extract PCAP records"""
        file = PCAPFile(Frames.dissect(data))
        hdr = PCAPFile.File_Header[file]
        yield FrameOutput(hdr)
        for i, rec in enumerate(PCAPRecordIterator(file)):
            yield FrameOutput(rec, PacketRecord.Packet_Data)

    def _extract_ethernet_frames(self, data: RawData) -> Iterable[FrameOutput]:
        """Extract Ethernet frames"""
        frame = EthernetII(Frames.dissect(data))
        return [FrameOutput(frame, EthernetII.data)]

    def extract(self, data: RawData, stack: List[Frame] = None) -> Iterable[FrameOutput]:
        if stack is None:
            stack = []
        while data:
            frame_it = self.process(data)
            for out in frame_it:
                if self.next:
                    if out.payload:
                        sub_data = out.payload[out.frame]
                        for sub in self.next.extract(sub_data, stack + [out.frame]):
                            yield sub
                else:
                    yield out
                frame_len = out.frame.byte_length()
                data = data.tailBytes(frame_len)


def main():
    # Create the argument parser
    parser = argparse.ArgumentParser(description='PCAP printing tool')
    parser.add_argument('-f', '--filter', type=str, help='YAML-formatted packet filter')
    parser.add_argument('read', type=str, action='append', help='Read PCAP file(s)')
    args = parser.parse_args()

    # construct the filtering
    filter_d = yaml.safe_load(args.filter or "")
    extractor = FrameExtractor(filter_d or {})

    # print extracted frames from files
    for file in args.read or []:
        with pathlib.Path(file) as f:
            data = Raw.file(f)
            for fr in extractor.extract(data):
                print(f"{fr.frame}")


if __name__ == '__main__':
    main()