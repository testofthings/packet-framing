import argparse
import datetime
import logging
import math
import pathlib
import sys
from typing import Dict, List, Tuple, Set, Union, Optional, TextIO

from framing.data_queue import RawDataQueue
from framing.frame_types.dns_frames import DNSMessage, DNSQuestion, DNSName, RDATA, DNSResource
from framing.frame_types.ethernet_frames import Ethernet_Payloads, EthernetII
from framing.frame_types.ipv4_frames import IPv4, IP_Payloads
from framing.frame_types.pcap_frames import PCAPFile, PacketRecord, FileHeader
from framing.frame_types.tcp_frames import TCP, TCPFlag, TCPDataQueue
from framing.frame_types.udp_frames import UDP, UDP_Common_Payloads
from framing.frames import Frames
from framing.raw_data import Raw, IPAddress, RawData


class Description:
    """Description of an endpoint"""
    def __init__(self):
        self.source = False
        self.sessions = 0
        self.out_data = 0, 0, 0  # frames, data packets, data length
        self.in_data = 0, 0, 0  # ditto
        self.sub: Dict[str, Description] = {}
        self.locations: List[Tuple[str, int, datetime.datetime]] = []
        self.head: Optional[RawData] = None

    def get_description(self, key: str, create_if_needed=True) -> Optional['Description']:
        if not create_if_needed and key not in self.sub:
            return None
        return self.sub.setdefault(key, Description())

    def update_data(self, reverse: bool, data_bytes: int):
        if reverse:
            d = self.in_data
            self.in_data = d[0] + 1, d[1] + (1 if data_bytes else 0), d[2] + data_bytes
        else:
            d = self.out_data
            self.out_data = d[0] + 1, d[1] + (1 if data_bytes else 0), d[2] + data_bytes

class Session:
    """A TCP or UDP session"""
    def __init__(self):
        self.enabled = True
        self.head: Optional[RawData] = None
        self.in_queue: Optional[TCPDataQueue] = None
        self.out_queue: Optional[TCPDataQueue] = None
        self.description: Optional[Description] = None


class PCAPScanner:
    """Scan PCAPs for attack surface measurements"""
    def __init__(self, name="default"):
        self.logger = logging.getLogger("scanner")
        self.name = name
        self.source: Tuple[str, int] = "", -1
        self.now = datetime.datetime.now()
        self.time_range = datetime.datetime.now(), datetime.datetime.fromtimestamp(0)
        # self.time_unit = datetime.timedelta(days=1)
        self.time_unit = datetime.timedelta(hours=6)
        self.time_unit_count = -1
        self.file_count = 0
        self.pcap_frame_count = 0
        self.description = Description()
        self.ethernet_data_type_count: Dict[int, int] = {}
        self.ip_data_type_count: Dict[int, int] = {}
        self.sessions: Dict[Tuple[str, IPAddress, int, IPAddress, int], Session] = {}
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
        file_name = file.as_posix()
        # Use Raw.stream to test/profile stream handling
        raw_data = Raw.file(file)
        # raw_data = Raw.stream(file.open("rb"), request_size=1 << 20)
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
                self.source = file_name, frame_num
                self.pcap_frame_count += 1

                ts_s = PacketRecord.Timestamp[rec]
                ts = datetime.datetime.fromtimestamp(ts_s)
                self.now = ts
                self.time_range = min(ts, self.time_range[0]), max(ts, self.time_range[1])

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
                    Frames.process(IPv4.Payload[ip], procs)

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

        rev, ses = self.update_transport("tcp", src_hw, src_ip, src_port, dst_hw, dst_ip, dst_port)
        if not ses:
            return

        flags = TCP.Flags[tcp]

        if not ses.out_queue:
            # fresh session, check that starts with handshake
            if flags & TCPFlag.SYN == 0:
                self.logger.warning("continuation TCP stream ignored at %s %d", self.source[0], self.source[1])
                ses.enabled = False  # not initial handshake
            else:
                # start collecting data
                ses.out_queue = TCPDataQueue(tcp)
        if not ses.in_queue and rev:
            if flags & TCPFlag.SYN == 0:
                self.logger.warning("continuation TCP stream ignored at %s %d", self.source[0], self.source[1])
                ses.enabled = False  # not initial handshake
            else:
                ses.in_queue = TCPDataQueue(tcp)

        if not ses.enabled:
            return

        data_len = TCP.Data.get_bit_length(tcp) // 8
        ses.description.update_data(rev, data_len)
        if not rev:
            if not ses.out_queue.is_closed():
                ses.out_queue.push_frame(tcp)
        else:
            if not ses.in_queue.is_closed():
                ses.in_queue.push_frame(tcp)

        if ses.head is None:
            # pick session head, update description head
            d = ses.description
            head = TCP.Data[tcp].subBlock(0, 8)
            if head:
                ses.head = head
                if d.head is None:
                    d.head = head
                else:
                    d.head = d.head.joint_head(head)

        if flags & TCPFlag.FIN or flags & TCPFlag.RST:
            # end of data
            if not rev:
                ses.out_queue.close()
            else:
                ses.in_queue.close()

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
        rev, ses = self.update_transport("udp", src_hw, src_ip, src_port, dst_hw, dst_ip, dst_port)

        data_len = UDP.Data.get_bit_length(udp) // 8
        if ses:
            ses.description.update_data(rev, data_len)

        if ses and ses.head is None:
            # pick session head, update description head
            d = ses.description
            head = UDP.Data[udp].subBlock(0, 8)
            if head:
                ses.head = head
                if d.head is None:
                    d.head = head
                else:
                    d.head = d.head.joint_head(head)

    def update_transport(self, protocol: str, src_hw: RawData, src_ip: IPAddress, src_port: int,
                         dst_hw: RawData, dst_ip: IPAddress, dst_port: int) -> Tuple[bool, Optional[Session]]:
        ses, rev_dir, new_s = self.session_for((protocol, src_ip, src_port, dst_ip, dst_port))

        if new_s:
            if src_ip.is_global and not dst_ip.is_global:
                self.logger.warning("Global => private %s => %s ignored at %s %d", src_ip, dst_ip,
                                    self.source[0], self.source[1])
                del self.sessions[(protocol, src_ip, src_port, dst_ip, dst_port)]
                return False, None

        if not ses.enabled:
            return False, None  # disabled session

        ep_d = ses.description
        if not ep_d:
            # session not resolved
            if rev_dir:
                # going toward client
                src_d = self.get_description(dst_ip, dst_hw)
                # src_d.source = True
                dst_d = self.get_description(src_ip, src_hw, parent=src_d)
                ep_d = dst_d.get_description(f"{protocol}:{src_port}")
            else:
                # going towards server
                src_d = self.get_description(src_ip, src_hw)
                src_d.source = True

                dst_d = self.get_description(dst_ip, dst_hw, parent=src_d)
                ep_d = dst_d.get_description(f"{protocol}:{dst_port}")
            ep_d.sessions += 1
            ses.description = ep_d
        ep_d.locations.append((self.source[0], self.source[1], self.now))
        return rev_dir, ses

    def session_for(self, connection: Tuple[str, IPAddress, int, IPAddress, int]) -> Tuple[Session, bool, bool]:
        r_key = connection[0], connection[3], connection[4], connection[1], connection[2]
        ses = self.sessions.get(r_key)
        if ses:
            return ses, True, False  # reverse direction
        else:
            ses = self.sessions.get(connection)
            new_s = ses is None
            if new_s:
                # new session
                ses = Session()
                self.sessions[connection] = ses
            return ses, False, new_s  # forward direction

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
            Frames.process(DNSResource.RDATA[rd], proc_rd)

    def learn_dns_name(self, name: str, ip: IPAddress):
        self.dns_names[ip] = name

    def list_descriptions(self) -> List[Description]:
        """List descriptions with capture locations"""
        r = []

        def list_em(d: Description):
            if d.locations:
                r.append(d)
            for s in d.sub.values():
                list_em(s)
        list_em(self.description)
        return r

    def print_output(self, write_to: TextIO):
        """Print analysis output"""
        self.time_unit_count = math.ceil((self.time_range[1] - self.time_range[0]) / self.time_unit)

        write_to.write(f"{self}\n")
        d_list = self.list_descriptions()
        d_numbers = {d: i + 1 for i, d in enumerate(d_list)}
        for p, s in self.to_string(self.description, d_numbers):
            write_to.write((f"{p:04}" if p else "    ") + f" {s}\n")

        # location mapping
        write_to.write(f"Mappings:\n")
        for d in d_list:
            num = d_numbers.get(d, 0)
            for loc in d.locations:
                write_to.write(f"{num:04} " + loc[0].replace(' ', r'\ ') + f" {loc[1]}\n")

    def __repr__(self):
        r = []
        if self.name:
            r.append(f"## {self.name} ##")

        t_units = math.ceil((self.time_range[1] - self.time_range[0]) / self.time_unit)
        r.extend([
            f"PCAP files:   {self.file_count}",
            f"PCAP frames:  {self.pcap_frame_count}",
            f"Oldest frame: {self.time_range[0]}",
            f"Newest frame: {self.time_range[1]}",
            f"Time units:   {t_units} (unit {self.time_unit})",
        ])

        r.append("Ethernet payload types:")
        for t, c in sorted(self.ethernet_data_type_count.items()):
            r.append(f"  0x{t:04x}: {c}")

        r.append("IP payload types and addresses:")
        for t, c in sorted(self.ip_data_type_count.items()):
            r.append(f"  0x{t:02x}: {c}")
        return "\n".join(r)

    def to_string(self, description: Description, numbering: Dict['Description', int]) -> List[Tuple[int, str]]:
        r = []
        num = numbering.get(description, 0)
        if num > 0:
            # ts_set = set([round((loc[2] - self.time_range[0]) / self.time_unit) for loc in description.locations])
            # ts_str = "".join([("x" if t in ts_set else "-") for t in range(0, self.time_unit_count)])

            d = description
            head_s = f" head={d.head}" if d.head is not None else ""
            di = d.in_data
            do = d.out_data
            di_size = round(di[2] / di[1]) if di[1] else 0
            do_size = round(do[2] / do[1]) if do[1] else 0
            r.append((num, f"ses={d.sessions} inf={di[0]} ouf={do[0]} isize={di_size} osize={do_size}{head_s}"))

        for key, d in description.sub.items():
            dir_s = ""
            ind_s = f"  "
            if description.source and not d.source:
                dir_s = "=> "
                ind_s += "   "
            sub_s = self.to_string(d, numbering)
            if len(sub_s) == 1:
                r.append((sub_s[0][0], f"{dir_s}{key} {sub_s[0][1]}"))
                continue
            r.append((0, f"{dir_s}{key}"))
            for s in sub_s:
                r.append((s[0], f"{ind_s}{s[1]}"))

        return r


def separate_scans_by_directory(roots: List[pathlib.Path], output_dir: pathlib.Path, limit=0):
    s_count = 0
    for rf in roots:
        if not rf.is_dir():
            continue
        for f in rf.iterdir():
            s_count += 1
            if limit and s_count > limit:
                return
            file_name = f.name
            scn = PCAPScanner(file_name)
            scn.scan_files(list(f.iterdir()))
            output_dir.mkdir(parents=True, exist_ok=True)
            report_f = output_dir / file_name
            print(f"Output to {report_f.as_posix()}")
            with report_f.open("wt") as rf:
                scn.print_output(rf)


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
        separate_scans_by_directory(files, pathlib.Path("pcap-analysis"), limit)
    else:
        scanner = PCAPScanner()
        scanner.scan_files(files, limit)
        scanner.print_output(sys.stdout)

