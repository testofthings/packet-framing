import argparse
import logging
import os
import pathlib

from framing.frame_types.ethernet_frames import Ethernet_Payloads
from framing.frame_types.ipv4_frames import IP_Payloads
from framing.frame_types.ipv6_frames import IPv6_Payloads
from framing.frame_types.pcap_frames import PCAPFile, PCAP_Payloads
from framing.frame_types.udp_frames import UDP_Common_Payloads
from framing.frames import Frames
from framing.raw_data import Raw

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("files", action="append", help="PCAPs file to read")
    parser.add_argument("-l", "--log", dest="log_level", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help="Set the logging level", default=None)
    parser.add_argument("--frame", type=int, default=-1, help="Start from given frame")
    parser.add_argument("--silent", action="store_true", help="Run silent (for performance analysis?)")
    args = parser.parse_args()
    silent = args.silent
    start_frame = args.frame
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
        IP_Payloads.add_to(pcap)
        IPv6_Payloads.add_to(pcap)
        UDP_Common_Payloads.add_to(pcap)

        hdr = PCAPFile.File_Header[pcap]
        if not silent and start_frame == -1:
            print(f"{Frames.dump(hdr, bit_offset=offset, width=wid)}")
        offset += hdr.bit_length()

        for i, rec in enumerate(PCAPFile.Packet_Records.iterate(pcap)):
            if start_frame - 1 > i:
                continue
            if not silent:
                print(f"=== #{i + 1} ===")
                print(f"{Frames.dump(rec, bit_offset=offset, width=wid, indent='  ')}")
            offset += rec.bit_length()

        print(f"Total length: {offset // 8} bytes")

