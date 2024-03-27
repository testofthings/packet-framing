import argparse
import pathlib
from typing import Any, Callable, Dict, Iterable, Type
import yaml

from framing.backends import RawFrame
from framing.base import Field, Frame
from framing.frame_types.pcap_frames import PCAPFile, PCAPRecordIterator, PacketRecord
from framing.frames import Frames
from framing.raw_data import Raw, RawData


class FrameExtractor:
    """Extract frames from raw data using a specification"""
    def __init__(self, spec: Dict[Any, Any]):
        self._build(spec)
        self.process: Callable[[RawData], Iterable[Frame]] = self._no_processing
        self._build(spec)

    def _no_processing(self, data: RawData) -> Frame:
        return [RawFrame(Frames.dissect(data))]

    def _build(self, spec: Dict[Any, Any]):
        """Build this extractor recursively"""
        for k, v in spec.items():
            if k == 'pcap':
                self.process = self._extract_pcap_records

    def _extract_pcap_records(self, data: RawData) -> Iterable[RawData]:
        """Extract PCAP records"""
        file = PCAPFile(Frames.dissect(data))
        hdr = PCAPFile.File_Header[file]
        yield hdr
        for i, rec in enumerate(PCAPRecordIterator(file)):
            yield rec

    def extract(self, data: RawData) -> Iterable[Frame]:
        while data:
            frame_it = self.process(data)
            for frame in frame_it:
                yield frame
                frame_len = frame.byte_length()
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
                print(f"{fr}")


if __name__ == '__main__':
    main()