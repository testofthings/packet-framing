import pathlib

from framing.frame_types.ethernet_frames import Ethernet_Payloads, EthernetII
from framing.frame_types.ipv4_frames import IPv4
from framing.frame_types.pcap_frames import PCAPFile, PCAP_Payloads, PacketRecord
from framing.frame_types.tcp_frames import TCP, TCPFlag
from framing.frames import Frames
from framing.raw_data import Raw


def test_decode_tcp():
    pcap = PCAPFile.open_file(pathlib.Path("samples/sample-1-head.pcap"), mappings=PCAP_Payloads + Ethernet_Payloads)

    raw = IPv4.Payload[PCAPFile.Packet_Records.item(pcap, 0) / PacketRecord.Packet_Data / EthernetII.data]
    tcp = TCP(Frames.dissect(raw))
    assert TCP.Checksum[tcp] == Raw.octets(0x84, 0x25)
    assert TCP.Data[tcp] == Raw.empty
    assert TCP.Flags[tcp] & TCPFlag.FIN == 0
    assert TCP.Flags[tcp] & TCPFlag.ACK != 0

    raw = IPv4.Payload[PCAPFile.Packet_Records.item(pcap, 6) / PacketRecord.Packet_Data / EthernetII.data]
    tcp = TCP(Frames.dissect(raw))
    assert TCP.Checksum[tcp] == Raw.octets(0x7d, 0x12)
    assert TCP.Source_port[tcp] == 64973
    assert TCP.Destination_port[tcp] == 443
    assert TCP.Options[tcp].byte_length() == 12
    assert TCP.Data[tcp].byte_length() == 24
