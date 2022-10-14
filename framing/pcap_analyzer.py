import argparse
import logging
import pathlib
from typing import Dict, List, Tuple, Set, Union, Optional

from framing.frame_types.dns_frames import DNSMessage, DNSQuestion, DNSName, RDATA, DNSResource
from framing.frame_types.ethernet_frames import Ethernet_Payloads, EthernetII
from framing.frame_types.ipv4_frames import IPv4, IP_Payloads
from framing.frame_types.pcap_frames import PCAPFile, PacketRecord, FileHeader
from framing.frame_types.tcp_frames import TCP, TCPFlag
from framing.frame_types.udp_frames import UDP, UDP_Common_Payloads
from framing.frames import Frames
from framing.raw_data import Raw, IPAddress, RawData


class Description:
    def __init__(self):
        self.source = False
        self.out_frames = 0
        self.in_frames = 0
        self.sub: Dict[str, Description] = {}

    def get_description(self, key: str, create_if_needed=True) -> Optional['Description']:
        if not create_if_needed and key not in self.sub:
            return None
        return self.sub.setdefault(key, Description())

    def __repr__(self):
        r = []
        if self.in_frames or self.out_frames:
            r.append(f"inf={self.in_frames} ouf={self.out_frames}")
        for key, d in self.sub.items():
            dir_s = ""
            ind_s = "  "
            if self.source and not d.source:
                dir_s = "=> "
                ind_s += "   "
            sub_s = d.__repr__()
            if "\n" not in sub_s:
                r.append(f"{dir_s}{key} {sub_s}")
                continue
            r.append(f"{dir_s}{key}")
            if not sub_s:
                continue
            for s in sub_s.split("\n"):
                r.append(f"{ind_s}{s}")

        return "\n".join(r)


class PCAPScanner:
    """Scan PCAPs for attack surface measurements"""
    def __init__(self, name=""):
        self.logger = logging.getLogger("scanner")
        self.name = name
        self.file_count = 0
        self.pcap_frame_count = 0
        self.description = Description()
        self.ethernet_data_type_count: Dict[int, int] = {}
        self.ip_data_type_count: Dict[int, int] = {}
        self.sessions: Set[Tuple[str, IPAddress, int, IPAddress, int]] = set()
        self.dns_names: Dict[IPAddress, str] = {}
        self.asked_dns_names: Set[str] = set()

    def scan_files(self, file_list: List[pathlib.Path], limit=0):
        for file in sorted(file_list):
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
                        TCP: lambda f: self.scan_tcp(eth, ip, f),
                        UDP: lambda f: self.scan_udp(eth, ip, f),
                    }
                    IPv4.Payload.process_frame(ip, procs)

        finally:
            raw_data.close()

    def get_description(self, for_ip: IPAddress, hw_address: RawData, parent: Description = None) -> Description:
        if parent is None:
            parent = self.description
        d_name = self.dns_names.get(for_ip)
        if d_name:
            return parent.get_description(d_name).get_description(f"{for_ip}")
        elif not for_ip.is_global:
            # local address
            return parent.get_description(hw_address.as_hw_address()).get_description(f"{for_ip}")
        else:
            return parent.get_description(f"{for_ip}")

    def scan_tcp(self, eth: EthernetII, ip: IPv4, tcp: TCP):
        src_hw = EthernetII.source[eth]
        src_ip = IPv4.Source_IP[ip].as_ip_address()
        src_port = TCP.Source_port[tcp]
        dst_hw = EthernetII.destination[eth]
        dst_ip = IPv4.Destination_IP[ip].as_ip_address()
        dst_port = TCP.Destination_port[tcp]

        # FIXME: Expect SYN?
        #flags = TCP.Flags[tcp]
        #if flags & TCPFlag.SYN == 0 or flags & TCPFlag.ACK != 0:
        #    return  # not initial handshake

        self.update_transport("tcp", src_hw, src_ip, src_port, dst_hw, dst_ip, dst_port)

    def scan_udp(self, eth: EthernetII, ip: IPv4, udp: TCP):
        procs = {
            DNSMessage: self.scan_dns,
        }
        UDP.Data.process_frame(udp, procs)

        src_hw = EthernetII.source[eth]
        src_ip = IPv4.Source_IP[ip].as_ip_address()
        src_port = UDP.Source_port[udp]
        dst_hw = EthernetII.destination[eth]
        dst_ip = IPv4.Destination_IP[ip].as_ip_address()
        dst_port = UDP.Destination_port[udp]

        self.update_transport("udp", src_hw, src_ip, src_port, dst_hw, dst_ip, dst_port)

    def update_transport(self, protocol: str, src_hw: RawData, src_ip: IPAddress, src_port: int,
                         dst_hw: RawData, dst_ip: IPAddress, dst_port: int):
        rev_dir, new_s = self.session_for((protocol, src_ip, src_port, dst_ip, dst_port))

        if new_s:
            if src_ip.is_global and not dst_ip.is_global:
                self.logger.warning("Connection %s => %s from global to private, ignoring", src_ip, dst_ip)
                self.sessions.remove((protocol, src_ip, src_port, dst_ip, dst_port))
                return

        if rev_dir:
            # going toward client
            src_d = self.get_description(dst_ip, dst_hw)
            # src_d.source = True
            dst_d = self.get_description(src_ip, src_hw, parent=src_d)
            ep_d = dst_d.get_description(f"{protocol}:{src_port}")
            ep_d.in_frames += 1
        else:
            # going towards server
            src_d = self.get_description(src_ip, src_hw)
            src_d.source = True

            dst_d = self.get_description(dst_ip, dst_hw, parent=src_d)
            ep_d = dst_d.get_description(f"{protocol}:{dst_port}")
            ep_d.out_frames += 1

    def session_for(self, connection: Tuple[str, IPAddress, int, IPAddress, int]) -> Tuple[bool, bool]:
        r_key = connection[0], connection[3], connection[4], connection[1], connection[2]
        dir_in = r_key in self.sessions
        if dir_in:
            self.sessions.add(r_key)
            return True, False
        else:
            new_s = connection not in self.sessions
            self.sessions.add(connection)
            return dir_in, new_s

    def scan_dns(self, frame: DNSMessage):
        for qn in DNSMessage.Question.iterate(frame):
            name = DNSName.string(qn, DNSQuestion.QNAME)
            self.asked_dns_names.add(name)

        for rd in DNSMessage.Answer.iterate(frame):
            name = DNSName.string(rd, DNSResource.NAME)
            proc_rd = {
                RDATA.A: lambda r: self.learn_dns_name(name, r.as_ip_address()),
                RDATA.AAAA: lambda r: self.learn_dns_name(name, r.as_ip_address()),
            }
            DNSResource.RDATA.process_frame(rd, proc_rd)

    def learn_dns_name(self, name: str, ip: IPAddress):
        self.dns_names[ip] = name

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

        r.append(f"{self.description}")
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

