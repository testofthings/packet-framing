import argparse
import logging
import os
import pathlib
from typing import Dict, List

from framing.frame_types.ethernet_frames import Ethernet_Payloads, EthernetII
from framing.frames import Frames
from framing.frame_types.pcap_frames import PCAPFile, PCAP_Payloads, PacketRecord, FileHeader
from framing.raw_data import Raw


class PCAPScanner:
    """Scan PCAPs for attack surface measurements"""
    def __init__(self):
        self.logger = logging.getLogger("scanner")
        self.file_count = 0
        self.pcap_frame_count = 0
        self.ethernet_data_type_count: Dict[int, int] = {}

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
            self.scan_pcap_file(file)

    def scan_pcap_file(self, file: pathlib.Path):
        raw_data = Raw.file(file)
        offset = 0
        try:
            pcap = PCAPFile(Frames.dissect(raw_data))
            PCAP_Payloads.add_to(pcap)
            Ethernet_Payloads.add_to(pcap)

            hdr = PCAPFile.File_Header[pcap]
            assert FileHeader.LinkType[hdr] == 1, "Non-Ethernet capture not supported"
            offset += hdr.get_bit_length()

            for i, rec in enumerate(PCAPFile.Packet_Records.iterate(pcap)):
                offset += rec.get_bit_length()
                self.pcap_frame_count += 1
                eth = PacketRecord.Packet_Data[rec]
                data_type = EthernetII.type[eth]
                self.ethernet_data_type_count[data_type] = self.ethernet_data_type_count.get(data_type, 0) + 1
        finally:
            raw_data.close()

    def __repr__(self):
        r = [
            f"PCAP files:   {self.file_count}",
            f"PCAP frames:  {self.pcap_frame_count}",
        ]

        r.append("Ethernet payload types:")
        for t, c in self.ethernet_data_type_count.items():
            r.append(f"  {t:04x}: {c}")
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

