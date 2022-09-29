import argparse
import logging
import os
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

    try:
        wid, _ = os.get_terminal_size(0)
    except OSError:
        wid = 80

    offset = 0
    for f_name in args.files:
        raw_data = Raw.file(pathlib.Path(f_name))
        pcap = PCAPFile(Frames.dissect(raw_data))

        hdr = PCAPFile.File_Header[pcap]
        print(f"{Frames.dump(hdr, bit_offset=offset, width=wid)}")
        offset += hdr.get_bit_length()

        for i, rec in enumerate(PCAPFile.Packet_Records.iterate(pcap)):
            print(f"=== #{i} ===")
            print(f"{Frames.dump(rec, bit_offset=offset, width=wid, indent='  ')}")
            offset += rec.get_bit_length()


