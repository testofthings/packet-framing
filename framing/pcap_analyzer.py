import argparse
import logging
import os
import pathlib
from typing import Dict, List

from framing.frame_types.ethernet_frames import Ethernet_Payloads
from framing.frames import Frames
from framing.frame_types.pcap_frames import PCAPFile, PCAP_Payloads
from framing.raw_data import Raw


class PCAPScanner:
    """Scan PCAPs for attack surface measurements"""
    def __init__(self):
        self.logger = logging.getLogger("scanner")
        self.file_count = 0

    def scan_files(self, file_list: List[pathlib.Path]):
        for file in file_list:
            if file.is_dir():
                self.scan_files(list(file.iterdir()))
                continue
            if not file.suffix == ".pcap":
                self.logger.info("skip file %s", file.as_posix())
                continue
            self.file_count += 1
            self.logger.info("Scan file %s", file.as_posix())

    def scan_pcap_file(self, file: pathlib.Path):
        raw_data = Raw.file(file)
        offset = 0
        try:
            pcap = PCAPFile(Frames.dissect(raw_data))
            PCAP_Payloads.add_to(pcap)
            Ethernet_Payloads.add_to(pcap)

            hdr = PCAPFile.File_Header[pcap]
            offset += hdr.get_bit_length()

            for i, rec in enumerate(PCAPFile.Packet_Records.iterate(pcap)):
                offset += rec.get_bit_length()
        finally:
            raw_data.close()

    def __repr__(self):
        r = [
            f"PCAP files: {self.file_count}",
        ]
        return "\n".join(r)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("files", action="append", help="PCAPs file or directories to read")
    parser.add_argument("-l", "--log", dest="log_level", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help="Set the logging level", default=None)
    args = parser.parse_args()
    logging.basicConfig(format='%(message)s', level=getattr(logging, args.log_level or 'INFO'))

    scanner = PCAPScanner()
    scanner.scan_files([pathlib.Path(n) for n in args.files])
    print(f"{scanner}")

