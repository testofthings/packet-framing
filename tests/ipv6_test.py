import pathlib

from framing.frame_types.ethernet_frames import EthernetII, Ethernet_Payloads
from framing.frame_types.ipv6_frames import IPReassembler, IPStackLayer, IPv6, IPv6_Payloads, IPv6ExtensionHeader, \
    Header, ICMPv6, Fragment
from framing.frame_types.pcap_frames import FileHeader, PCAPFile, PacketRecord, PCAP_Payloads, frame_for_link_type
from framing.frame_types.tcp_frames import TCP, TCPFlag
from framing.frame_types.udp_frames import UDP
from framing.frames import Frames
from framing.raw_data import Raw


# Packets below are hand-built (no suitable pcaps around). Addresses are made up (fe80::1 / fe80::2).
_SRC_ADDRESS = bytes.fromhex("fe80") + bytes(13) + bytes([1])
_DST_ADDRESS = bytes.fromhex("fe80") + bytes(13) + bytes([2])


def _ipv6_packet(next_header: int, payload: bytes, hop_limit: int = 64) -> bytes:
    """Build a full IPv6 packet (40-byte fixed header) around the given already-encoded payload bytes"""
    header = bytearray([0x60, 0x00, 0x00, 0x00])  # version 6, traffic class 0, flow label 0
    header += len(payload).to_bytes(2, "big")
    header += bytes([next_header, hop_limit])
    header += _SRC_ADDRESS
    header += _DST_ADDRESS
    return bytes(header) + payload


def _ext_header(next_header: int, header_ext_length: int = 0) -> bytes:
    """Build a generic IPv6 extension header"""
    total_length = (header_ext_length + 1) * 8
    return bytes([next_header, header_ext_length]) + bytes(total_length - 2)


def _udp_datagram(source_port: int, destination_port: int, data: bytes) -> bytes:
    """Build a UDP datagram (8-byte fixed header) around the given payload bytes"""
    length = 8 + len(data)
    return source_port.to_bytes(2, "big") + destination_port.to_bytes(2, "big") + \
        length.to_bytes(2, "big") + bytes(2) + data


def _tcp_segment(source_port: int, destination_port: int, seq: int, ack: int, flags: int, data: bytes) -> bytes:
    """Build a TCP segment (20-byte fixed header) around the given payload bytes"""
    data_offset_and_flags = (5 << 12) | flags  # data offset 5: fixed header only, no TCP options
    return source_port.to_bytes(2, "big") + destination_port.to_bytes(2, "big") + \
        seq.to_bytes(4, "big") + ack.to_bytes(4, "big") + data_offset_and_flags.to_bytes(2, "big") + \
        bytes(2) + bytes(2) + bytes(2) + data


def test_decode_ip():
    pcap = PCAPFile.open_file(pathlib.Path("samples/ipv6-neighbor-solicitation.pcap"), mappings=PCAP_Payloads)

    raw_ip = EthernetII.data[PCAPFile.Packet_Records.item(pcap, 0) / PacketRecord.Packet_Data]
    ip = IPv6(Frames.dissect(raw_ip, mappings=IPv6_Payloads))

    assert IPv6.Version[ip] == 6
    assert IPv6.Traffic_class[ip] == 0
    assert str(IPv6.Source_address[ip].as_ip_address()) == "fe80::9400:1ff:fe98:e866"
    assert str(IPv6.Destination_address[ip].as_ip_address()) == "ff02::1:ff00:1"
    assert IPv6.Payload[ip].byte_length() == 32

    ic = IPv6.Payload.as_frame(ip)
    assert isinstance(ic, ICMPv6)

    Frames.close(pcap)


def test_decode_ip_assemble():
    assembler = IPReassembler()
    pcap = PCAPFile.open_file(pathlib.Path("samples/tls13-over-ipv6.pcap"), mappings=PCAP_Payloads)
    link_type = FileHeader.LinkType[PCAPFile.File_Header[pcap]]
    pays = []
    for rec in PCAPFile.Packet_Records.iterate(pcap):
        frame = frame_for_link_type(link_type, PacketRecord.Packet_Data[rec])
        assert isinstance(frame, EthernetII)
        ip_frame = EthernetII.data.as_frame(frame, frame_type=IPv6)
        assert IPv6.Version[ip_frame] == 6
        pay = assembler.push_frame(ip_frame)
        if pay is not None:
            pays.append(pay)

    assert all (isinstance(p, TCP) for p in pays)
    Frames.close(pcap)


def test_decode_headers():
    pcap = PCAPFile.open_file(pathlib.Path("samples/ipv6-udp-frag.pcap"),
                              mappings=PCAP_Payloads + Ethernet_Payloads + IPv6_Payloads)

    fr = IPv6.Payload.as_frame(PCAPFile.Packet_Records.item(pcap, 0) / PacketRecord.Packet_Data / EthernetII.data)
    udp = Fragment.Payload.as_frame(fr)
    assert UDP.Length[udp] == 16392

    # NOTE: UDP is split into 12 fragments!


def test_decode_ip6_tcp():
    pcap = PCAPFile.open_file(pathlib.Path("samples/tls13-over-ipv6.pcap"),
                                mappings=PCAP_Payloads + Ethernet_Payloads + IPv6_Payloads)
    fr0 = PCAPFile.Packet_Records.item(pcap, 0) / PacketRecord.Packet_Data / EthernetII.data
    assert IPv6.Source_address[fr0] == Raw.hex("2a 00 1d 50 00 03 00 00 ac 3a 30 a5 20 41 35 44")
    assert IPv6.Destination_address[fr0] == Raw.hex("2a 04 fa 87 ff fe 00 00 00 00 00 00 c0 00 49 02")
    assert IPv6.Payload_length[fr0] == 40
    pl0 = IPv6.Payload.as_frame(fr0)
    assert TCP.Checksum[pl0] == Raw.hex("692a")


def test_hop_by_hop_options_then_udp():
    """Hop-by-Hop Options extension header immediately followed by a UDP datagram"""
    udp = _udp_datagram(53125, 53, "hello".encode())
    ext = _ext_header(next_header=17, header_ext_length=0)  # next: UDP
    raw = _ipv6_packet(next_header=Header.Hop_by_Hop_Options, payload=ext + udp)

    ip = IPv6(Frames.dissect(Raw.hex(raw.hex()), mappings=IPv6_Payloads))
    assert IPv6.Next_header[ip] == Header.Hop_by_Hop_Options
    assert IPv6.Payload_length[ip] == len(ext) + len(udp)

    ext_frame = IPv6.Payload.as_frame(ip)
    assert isinstance(ext_frame, IPv6ExtensionHeader)
    assert IPv6ExtensionHeader.Next_Header[ext_frame] == 17
    assert IPv6ExtensionHeader.Header_Ext_Length[ext_frame] == 0
    assert IPv6ExtensionHeader.Options[ext_frame].byte_length() == 6

    # the extension header's own payload field resolves straight to UDP via the layer mapping
    udp_frame = IPv6ExtensionHeader.Payload.as_frame(ext_frame)
    assert isinstance(udp_frame, UDP)
    assert UDP.Source_port[udp_frame] == 53125
    assert UDP.Destination_port[udp_frame] == 53
    assert UDP.Data[udp_frame] == Raw.string("hello")

    # get_payload() walks the same chain and additionally reports the resolved protocol number
    pay_type, pay = ip.get_payload()
    assert pay_type == 17
    assert isinstance(pay, UDP)
    assert UDP.Data[pay] == Raw.string("hello")


def test_routing_header_then_tcp():
    """Routing extension header immediately followed by a TCP segment"""
    tcp = _tcp_segment(443, 51820, seq=1000, ack=0, flags=TCPFlag.SYN, data="hi".encode())
    ext = _ext_header(next_header=6, header_ext_length=0)  # next: TCP
    raw = _ipv6_packet(next_header=Header.Routing, payload=ext + tcp)

    ip = IPv6(Frames.dissect(Raw.hex(raw.hex()), mappings=IPv6_Payloads))
    pay_type, pay = ip.get_payload()
    assert pay_type == 6
    assert isinstance(pay, TCP)
    assert TCP.Source_port[pay] == 443
    assert TCP.Destination_port[pay] == 51820
    assert TCP.Flags[pay] & TCPFlag.SYN
    assert TCP.Data[pay] == Raw.string("hi")


def test_chained_extension_headers_then_udp():
    """Hop-by-Hop Options -> Routing -> UDP: several extension headers stacked before the transport payload"""
    udp = _udp_datagram(9999, 8888, "chained".encode())
    routing = _ext_header(next_header=17, header_ext_length=1)  # 16-byte header, next: UDP
    hop_by_hop = _ext_header(next_header=Header.Routing, header_ext_length=0)  # 8-byte header, next: Routing
    raw = _ipv6_packet(next_header=Header.Hop_by_Hop_Options, payload=hop_by_hop + routing + udp)

    ip = IPv6(Frames.dissect(Raw.hex(raw.hex()), mappings=IPv6_Payloads))
    pay_type, pay = ip.get_payload()
    assert pay_type == 17
    assert isinstance(pay, UDP)
    assert UDP.Source_port[pay] == 9999
    assert UDP.Data[pay] == Raw.string("chained")


def test_extension_header_length_field_math():
    """Header_Ext_Length is in 8-octet units, not counting the first 8 octets (RFC 8200)"""
    for hel, expected_option_bytes in ((0, 6), (1, 14), (3, 30)):
        raw = _ext_header(next_header=17, header_ext_length=hel)
        eh = IPv6ExtensionHeader(Frames.dissect(Raw.hex(raw.hex())))
        assert IPv6ExtensionHeader.Header_Ext_Length[eh] == hel
        assert IPv6ExtensionHeader.Options[eh].byte_length() == expected_option_bytes
        assert eh.byte_length() == (hel + 1) * 8


def test_reassembler_push_frame_after_extension_header():
    """Test IPReassembler.push_frame() with an extension header before the transport payload."""
    udp = _udp_datagram(53125, 53, "hello".encode())
    ext = _ext_header(next_header=17, header_ext_length=0)  # next: UDP
    raw = _ipv6_packet(next_header=Header.Hop_by_Hop_Options, payload=ext + udp)

    # dissected the same way IPStackLayer/IPReassembler callers do: no IPv6_Payloads mapping yet,
    # push_frame() is expected to apply that mapping itself
    ip = IPv6(Frames.dissect(Raw.hex(raw.hex())))

    result = IPReassembler().push_frame(ip)
    assert isinstance(result, UDP), f"expected UDP, got {type(result)}"
    assert UDP.Source_port[result] == 53125
    assert UDP.Data[result] == Raw.string("hello")


def test_stack_layer_push_frame_after_extension_header():
    """Test IPStackLayer.push_frame() with an extension header before the transport payload."""
    tcp = _tcp_segment(443, 51820, seq=1000, ack=0, flags=TCPFlag.SYN, data="hi".encode())
    ext = _ext_header(next_header=6, header_ext_length=0)  # next: TCP
    raw = _ipv6_packet(next_header=Header.Routing, payload=ext + tcp)

    ip = IPv6(Frames.dissect(Raw.hex(raw.hex())))

    result = IPStackLayer().push_frame(ip)
    assert isinstance(result, TCP), f"expected TCP, got {type(result)}"
    assert TCP.Source_port[result] == 443
    assert TCP.Data[result] == Raw.string("hi")


def test_payload_length_bounds_payload():
    """Check that IPv6.Payload_length is used to bound the payload"""
    icmp_body = "ECHO".encode()
    icmp = bytes([128, 0, 0, 0]) + icmp_body  # type, code, checksum(2), body
    trailing_padding = bytes(10)  # e.g. Ethernet padding appended after a short IPv6 packet
    raw = _ipv6_packet(next_header=Header.ICMPv6, payload=icmp) + trailing_padding

    ip = IPv6(Frames.dissect(Raw.hex(raw.hex()), mappings=IPv6_Payloads))
    assert IPv6.Payload_length[ip] == len(icmp)

    _, pay = ip.get_payload()
    assert isinstance(pay, ICMPv6)
    assert ICMPv6.Message_Body[pay] == Raw.string("ECHO")
