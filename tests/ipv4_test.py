import pathlib

from framing.frame_types.ethernet_frames import EthernetII
from framing.frame_types.pcap_frames import PCAPFile, PCAP_Payloads, PacketRecord
from framing.frames import Frames
from framing.frame_types.ipv4_frames import IPv4
from framing.raw_data import Raw


def test_ipv4():
    ip = IPv4(Frames.compose())
    ip_s = f"{ip}"

    ip.encode()
    assert IPv4.Version[ip] == 4
    assert IPv4.IHL[ip] == 5
    assert IPv4.Total_Length[ip] == 20
    assert IPv4.Options[ip] == Raw.empty
    assert IPv4.Payload[ip] == Raw.empty

    # NOTE: Missing option structures and padding logic
    IPv4.Options[ip] = Raw.hex("01020304")
    ip.encode()
    assert IPv4.Version[ip] == 4
    assert IPv4.IHL[ip] == 6
    assert IPv4.Total_Length[ip] == 24
    assert IPv4.Options[ip] == Raw.hex("01020304")
    assert IPv4.Payload[ip] == Raw.empty


def test_decode_ip():
    b = Raw.file(pathlib.Path("samples/sample-1-head.pcap"))
    pcap = PCAPFile(Frames.dissect(b))
    PCAP_Payloads.add_to(pcap)

    rec = PCAPFile.Packet_Records.get_item(pcap, 0)
    eth = PacketRecord.Packet_Data.as_frame(rec)
    raw_ip = EthernetII.data[eth]

    ip = IPv4(Frames.dissect(raw_ip))

    assert IPv4.Version[ip] == 4
    assert IPv4.IHL[ip] == 5
    assert IPv4.Total_Length[ip] == 0x34
    assert IPv4.Options[ip] == Raw.empty
    assert ip.get_bit_length() == 0x34 * 8
