import argparse
import logging
import pathlib
from typing import Dict, List, Tuple, Set

from framing.frame_types.dns_frames import DNSMessage, DNSQuestion, DNSName, RDATA, DNSResource
from framing.frame_types.ethernet_frames import Ethernet_Payloads, EthernetII
from framing.frame_types.ipv4_frames import IPv4, IP_Payloads
from framing.frame_types.pcap_frames import PCAPFile, PacketRecord, FileHeader
from framing.frame_types.tcp_frames import TCP, TCPFlag
from framing.frame_types.udp_frames import UDP, UDP_Common_Payloads
from framing.frames import Frames
from framing.raw_data import Raw, IPAddress


class PCAPScanner:
    """Scan PCAPs for attack surface measurements"""
    def __init__(self, name=""):
        self.logger = logging.getLogger("scanner")
        self.name = name
        self.file_count = 0
        self.pcap_frame_count = 0
        self.ethernet_data_type_count: Dict[int, int] = {}
        self.ip_data_type_count: Dict[int, int] = {}
        self.ip_endpoints: Dict[Tuple[IPAddress, str], int] = {}
        self.dns_names: Dict[str, Set[IPAddress]] = {}

    def scan_files(self, file_list: List[pathlib.Path], limit=0):
        for file in file_list:
            if limit and self.file_count >= limit:
                return
            if file.is_dir():
                self.scan_files(list(file.iterdir()), limit)
                continue
            if not file.suffix == ".pcap":
                self.logger.info("skip file %s", file.as_posix())
                continue
            self.file_count += 1
            self.logger.info("Scan file %s", file.as_posix())
            self.scan_pcap_file(file)

    def scan_pcap_file(self, file: pathlib.Path):
        raw_data = Raw.file(file)
        try:
            pcap = PCAPFile(Frames.dissect(raw_data))
            # PCAP_Payloads.add_to(pcap)  # handle link type manually for performance
            Ethernet_Payloads.add_to(pcap)
            IP_Payloads.add_to(pcap)
            UDP_Common_Payloads.add_to(pcap)

            hdr = PCAPFile.File_Header[pcap]
            link_type = FileHeader.LinkType[hdr]
            assert link_type == 1, "Non-Ethernet capture not supported"

            frame_num = 0
            for i, rec in enumerate(PCAPFile.Packet_Records.iterate(pcap)):
                frame_num += 1
                self.pcap_frame_count += 1
                eth = PacketRecord.Packet_Data.as_frame(rec, frame_type=EthernetII)
                eth_dt = EthernetII.type[eth]
                self.ethernet_data_type_count[eth_dt] = self.ethernet_data_type_count.get(eth_dt, 0) + 1
                if eth_dt == 0x0800:
                    ip = EthernetII.data.as_frame(eth)
                    ip_td = IPv4.Protocol[ip]
                    self.ip_data_type_count[ip_td] = self.ip_data_type_count.get(ip_td, 0) + 1
                    procs = {
                        TCP: lambda f: self.scan_tcp(ip, f),
                        UDP: lambda f: self.scan_udp(ip, f),
                    }
                    IPv4.Payload.process_frame(ip, procs)

        finally:
            raw_data.close()

    def scan_tcp(self, ip: IPv4, tcp: TCP):
        flags = TCP.Flags[tcp]
        if flags & TCPFlag.SYN == 0 or flags & TCPFlag.ACK != 0:
            return  # not initial handshake
        src_ip, dst_ip = IPv4.Source_IP[ip].as_ip_address(), IPv4.Destination_IP[ip].as_ip_address()
        dst_port = TCP.Destination_port[tcp]
        ep = dst_ip, f"tcp:{dst_port}"
        self.ip_endpoints[ep] = self.ip_endpoints.get(ep, 0) + 1

    def scan_udp(self, ip: IPv4, udp: TCP):
        procs = {
            DNSMessage: self.scan_dns,
        }
        UDP.Data.process_frame(udp, procs)
        src_ip = IPv4.Source_IP[ip].as_ip_address()
        src_port = UDP.Source_port[udp]
        src_ep = src_ip, f"udp:{src_port}"
        if src_ep in self.ip_endpoints:
            # seen traffic _from_ here -> assume UDP client (FIXME: Could check addr-port pairs)
            return
        dst_ip = IPv4.Destination_IP[ip].as_ip_address()
        dst_port = UDP.Destination_port[udp]
        ep = dst_ip, f"udp:{dst_port}"
        self.ip_endpoints[ep] = self.ip_endpoints.get(ep, 0) + 1

    def scan_dns(self, frame: DNSMessage):
        for qn in DNSMessage.Question.iterate(frame):
            name = DNSName.string(qn, DNSQuestion.QNAME)
            self.dns_names.setdefault(name, set())

        for rd in DNSMessage.Answer.iterate(frame):
            name = DNSName.string(rd, DNSResource.NAME)
            proc_rd = {
                RDATA.A: lambda f: self.dns_names.setdefault(name, set()).add(f.as_ip_address()),
                RDATA.AAAA: lambda f: self.dns_names.setdefault(name, set()).add(f.as_ip_address()),
            }
            DNSResource.RDATA.process_frame(rd, proc_rd)

    def __repr__(self):
        r = []
        if self.name:
            r.append(f"## {self.name} ##")
        r.extend([
            f"PCAP files:   {self.file_count}",
            f"PCAP frames:  {self.pcap_frame_count}",
        ])

        r.append("Ethernet payload types:")
        for t, c in sorted(self.ethernet_data_type_count.items()):
            r.append(f"  0x{t:04x}: {c}")

        r.append("IP payload types and addresses:")
        for t, c in sorted(self.ip_data_type_count.items()):
            r.append(f"  0x{t:02x}: {c}")
        for a, c in sorted(self.ip_endpoints.items(), key=lambda x: f"{x[0]}"):
            r.append(f"  {a[0]}:{a[1]}: {c}")

        r.append("DNS names:")
        for n, ips in sorted(self.dns_names.items()):
            r.append(f"  {n}: " + " ".join([f"{i}" for i in ips]))
        return "\n".join(r)


def separate_scans_by_directory(roots: List[pathlib.Path], limit=0) -> List[PCAPScanner]:
    r = []
    for rf in roots:
        if not rf.is_dir():
            continue
        for f in rf.iterdir():
            if limit and len(r) >= limit:
                return r
            scn = PCAPScanner(f.name)
            scn.scan_files(list(f.iterdir()))
            r.append(scn)
    return r


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("files", action="append", help="PCAPs file or directories to read")
    parser.add_argument("--by-dir", action="store_true", help="Different scan for each subdirectory")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of scans or files (ease of testing)")
    parser.add_argument("-l", "--log", dest="log_level", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help="Set the logging level", default=None)
    args = parser.parse_args()
    logging.basicConfig(format='%(message)s', level=getattr(logging, args.log_level or 'INFO'))
    files = [pathlib.Path(n) for n in args.files]
    limit = args.limit

    if args.by_dir:
        scans = separate_scans_by_directory(files, limit)
        for s in scans:
            print(f"{s}")
    else:
        scanner = PCAPScanner()
        scanner.scan_files(files, limit)
        print(f"{scanner}")

