import argparse
import logging
import pathlib

from framing.frames import Frames
from framing.pcap_frames import PCAPFile
from framing.raw_data import Raw

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("files", action="append", help="PCAPs file to read")
    parser.add_argument("-l", "--log", dest="log_level", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help="Set the logging level", default=None)
    args = parser.parse_args()
    logging.basicConfig(format='%(message)s', level=getattr(logging, args.log_level or 'INFO'))

    for f_name in args.files:
        raw_data = Raw.file(pathlib.Path(f_name))
        pcap = PCAPFile(Frames.dissect(raw_data))
        print(f"{PCAPFile.File_Header[pcap]}")

        for i, rec in enumerate(PCAPFile.Packet_Records.iterate(pcap)):
            print(f"=== #{i} ===")
            print(f"{rec}")


