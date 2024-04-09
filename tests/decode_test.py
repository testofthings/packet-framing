import pathlib

import pytest

from framing.backends import RawFrame
from framing.frame_types.ethernet_frames import EthernetII
from framing.frame_types.ipv4_frames import IPv4
from framing.frame_types.pcap_frames import PCAPFile, PCAP_Payloads, PacketRecord
from framing.frames import Frames
from framing.raw_data import Raw


def test_partial_decode():
    pcap = PCAPFile.open_file(pathlib.Path("samples/sample-1-head.pcap"), mappings=PCAP_Payloads)
    ip_raw = EthernetII.data[PCAPFile.Packet_Records.item(pcap, 0) / PacketRecord.Packet_Data]

    full_ip = IPv4(Frames.dissect(ip_raw))
    assert full_ip.byte_length() == 52
    assert full_ip.bit_length() == 52 * 8

    ip = IPv4(Frames.dissect(Raw.empty))
    ip_s = f"{ip}"
    with pytest.raises(EOFError):
        ip_v = IPv4.Version[ip]
    with pytest.raises(EOFError):
        ip_len = ip.bit_length()

    ip = IPv4(Frames.dissect(ip_raw.subBlockBits(0, 1)))
    ip_s = f"{ip}"
    with pytest.raises(EOFError):
        ip_v = IPv4.Version[ip]
    with pytest.raises(EOFError):
        ip_len = ip.bit_length()

    ip = IPv4(Frames.dissect(ip_raw.subBlock(0, 1)))
    ip_s = f"{ip}"
    assert IPv4.Version[ip] == 4
    assert IPv4.IHL[ip] == 5
    with pytest.raises(EOFError):
        dscp = IPv4.DSCP[ip]
    with pytest.raises(EOFError):
        ip_len = ip.bit_length()

    ip = IPv4(Frames.dissect(ip_raw.subBlock(0, 10)))
    ip_s = f"{ip}"
    assert IPv4.Source_IP[ip] == Raw.hex("")
    assert IPv4.Destination_IP[ip] == Raw.hex("")
    with pytest.raises(EOFError):
        ip_len = ip.bit_length()

    ip = IPv4(Frames.dissect(ip_raw.subBlock(0, 14)))
    ip_s = f"{ip}"
    assert IPv4.Source_IP[ip] == Raw.hex("12c2")
    assert IPv4.Destination_IP[ip] == Raw.hex("")
    with pytest.raises(EOFError):
        ip_len = ip.bit_length()


def test_raw_data_frame():
    raw = Raw.octets(0)
    frame = RawFrame(Frames.dissect(raw))
    assert frame.byte_length() == 1
    assert frame.bit_length() == 8

    raw = Raw.empty
    frame = RawFrame(Frames.dissect(raw))
    assert frame.byte_length() == 0
    assert frame.bit_length() == 0
