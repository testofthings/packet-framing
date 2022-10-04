import argparse
import logging
import os
import pathlib

from framing.frame_types.ethernet_frames import Ethernet_Payloads
from framing.frames import Frames
from framing.frame_types.pcap_frames import PCAPFile, PCAP_Payloads
from framing.raw_data import Raw

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("files", action="append", help="PCAPs file to read")
    parser.add_argument("-l", "--log", dest="log_level", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help="Set the logging level", default=None)
    parser.add_argument("--silent", action="store_true", help="Run silent (for performance analysis?)")
    args = parser.parse_args()
    silent = args.silent
    logging.basicConfig(format='%(message)s', level=getattr(logging, args.log_level or 'INFO'))

    try:
        wid, _ = os.get_terminal_size(0)
    except OSError:
        wid = 80

    offset = 0
    for f_name in args.files:
        raw_data = Raw.file(pathlib.Path(f_name))
        pcap = PCAPFile(Frames.dissect(raw_data))
        PCAP_Payloads.add_to(pcap)
        Ethernet_Payloads.add_to(pcap)

        hdr = PCAPFile.File_Header[pcap]
        if not silent:
            print(f"{Frames.dump(hdr, bit_offset=offset, width=wid)}")
        offset += hdr.get_bit_length()

        for i, rec in enumerate(PCAPFile.Packet_Records.iterate(pcap)):
            if not silent:
                print(f"=== #{i + 1} ===")
                print(f"{Frames.dump(rec, bit_offset=offset, width=wid, indent='  ')}")
            offset += rec.get_bit_length()

        print(f"Total length: {offset // 8} bytes")

