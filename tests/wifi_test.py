"""Tests for IEEE 802.11 MAC frame parsing"""

import pathlib

from framing.frames import Frames
from framing.raw_data import Raw
from framing.frame_types.pcap_frames import PCAPFile, PacketRecord
from framing.frame_types.wifi_frames import (
    BlockAckReqBody,
    CTSBody,
    DataNullBody,
    QoSDataBody,
    Wifi80211FCFlags,
    Wifi80211Frame,
    Wifi80211_PCAP_Payloads,
)


def test_cts_decode():
    """CTS (Clear to Send) control frame — 10 bytes"""
    data = Raw.hex("d4 00  00 00  f6 e3 d1 31 ab 85")
    f = Wifi80211Frame(Frames.dissect(data))

    assert Wifi80211Frame.FC_TypeSubtype[f] == 0xD4
    assert Wifi80211Frame.FC_Flags[f] == 0x00

    body = Wifi80211Frame.body.get_choice(f)
    assert isinstance(body, CTSBody)
    assert CTSBody.Duration[body] == 0
    assert CTSBody.RA[body] == Raw.hex("f6 e3 d1 31 ab 85")
    assert f.byte_length() == 10


def test_block_ack_req_decode():
    """Block Ack Request control frame — 28 bytes"""
    data = Raw.hex(
        "94 00"                      # FC
        "00 00"                      # Duration
        "f6 e3 d1 31 ab 85"          # RA
        "b4 c2 e0 2b 6d 09"          # TA
        "04 00"                      # BAR Information (compressed bitmap, value=4)
        "80 07"                      # Starting Sequence Number (LE: 0x0780 = 1920)
        "ff ff ff ff ff ff ff ff"    # BAR Bitmap
    )
    f = Wifi80211Frame(Frames.dissect(data))

    assert Wifi80211Frame.FC_TypeSubtype[f] == 0x94
    assert Wifi80211Frame.FC_Flags[f] == 0x00

    body = Wifi80211Frame.body.get_choice(f)
    assert isinstance(body, BlockAckReqBody)
    assert BlockAckReqBody.Duration[body] == 0
    assert BlockAckReqBody.RA[body] == Raw.hex("f6 e3 d1 31 ab 85")
    assert BlockAckReqBody.TA[body] == Raw.hex("b4 c2 e0 2b 6d 09")
    assert BlockAckReqBody.BAR_Information[body] == 4
    assert BlockAckReqBody.Starting_Sequence_Number[body] == 0x0780  # seq 1920
    assert BlockAckReqBody.BAR_Bitmap[body] == Raw.hex("ffffffffffffffff")
    assert f.byte_length() == 28


def test_data_null_decode():
    """Data/Null frame (power-save notification) — 24 bytes"""
    data = Raw.hex(
        "48 11"                  # FC: type=Data subtype=Null, ToDS+PowerMgmt
        "6c 00"                  # Duration (LE: 108 µs)
        "b4 c2 e0 2b 6d 09"      # Addr1 (BSSID)
        "f6 e3 d1 31 ab 85"      # Addr2 (source)
        "b4 c2 e0 2b 6d 09"      # Addr3 (BSSID)
        "80 02"                  # Sequence Control (LE: 0x0280, frag=0 seq=40)
    )
    f = Wifi80211Frame(Frames.dissect(data))

    assert Wifi80211Frame.FC_TypeSubtype[f] == 0x48
    assert Wifi80211Frame.FC_Flags[f] & int(Wifi80211FCFlags.To_DS) != 0
    assert Wifi80211Frame.FC_Flags[f] & int(Wifi80211FCFlags.Power_Management) != 0
    assert Wifi80211Frame.FC_Flags[f] & int(Wifi80211FCFlags.From_DS) == 0

    body = Wifi80211Frame.body.get_choice(f)
    assert isinstance(body, DataNullBody)
    assert DataNullBody.Duration[body] == 108
    assert DataNullBody.Addr1[body] == Raw.hex("b4 c2 e0 2b 6d 09")
    assert DataNullBody.Addr2[body] == Raw.hex("f6 e3 d1 31 ab 85")
    assert DataNullBody.Addr3[body] == Raw.hex("b4 c2 e0 2b 6d 09")
    assert DataNullBody.Sequence_Control[body] == 0x0280  # frag=0, seq=40
    assert f.byte_length() == 24


def test_qos_data_decode():
    """QoS Data frame — variable length, testing fixed header fields"""
    data = Raw.hex(
        "88 02"                  # FC: type=Data subtype=QoS Data, FromDS
        "3c 00"                  # Duration (LE: 60 µs)
        "f6 e3 d1 31 ab 85"      # Addr1 (destination)
        "b4 c2 e0 2b 6d 09"      # Addr2 (BSSID/source)
        "b4 c2 e0 2b 6d 09"      # Addr3 (BSSID)
        "60 79"                  # Sequence Control (LE: 0x7960, frag=0, seq=1942)
        "00 00"                  # QoS Control
        "aa aa 03 00 00 00 08 00" # LLC SNAP header (EtherType 0x0800 = IPv4)
    )
    f = Wifi80211Frame(Frames.dissect(data))

    assert Wifi80211Frame.FC_TypeSubtype[f] == 0x88
    assert Wifi80211Frame.FC_Flags[f] & int(Wifi80211FCFlags.From_DS) != 0
    assert Wifi80211Frame.FC_Flags[f] & int(Wifi80211FCFlags.To_DS) == 0

    body = Wifi80211Frame.body.get_choice(f)
    assert isinstance(body, QoSDataBody)
    assert QoSDataBody.Duration[body] == 60
    assert QoSDataBody.Addr1[body] == Raw.hex("f6 e3 d1 31 ab 85")
    assert QoSDataBody.Addr2[body] == Raw.hex("b4 c2 e0 2b 6d 09")
    assert QoSDataBody.Addr3[body] == Raw.hex("b4 c2 e0 2b 6d 09")
    assert QoSDataBody.Sequence_Control[body] == 0x7960  # frag=0, seq=1942
    assert QoSDataBody.QoS_Control[body] == 0
    assert QoSDataBody.Frame_Body[body].byte_length() == 8  # LLC SNAP


def test_wifi_pcap_parse():
    """Parse the WiFi 802.11 PCAP sample and verify basic fields"""
    pcap = PCAPFile.open_file(
        pathlib.Path("samples/wifi_801_11.pcap"),
        mappings=Wifi80211_PCAP_Payloads,
    )
    records = PCAPFile.Packet_Records[pcap]
    assert len(records) == 47

    # Packet 1: CTS frame (10 bytes)
    pkt_data = PacketRecord.Packet_Data[records[0]]
    f = Wifi80211Frame(Frames.dissect(pkt_data))
    assert Wifi80211Frame.FC_TypeSubtype[f] == 0xD4
    body = Wifi80211Frame.body.get_choice(f)
    assert isinstance(body, CTSBody)
    assert CTSBody.RA[body] == Raw.hex("f6 e3 d1 31 ab 85")

    # Packet 9: QoS Data frame (1142 bytes, first big data packet)
    pkt_data = PacketRecord.Packet_Data[records[8]]
    f = Wifi80211Frame(Frames.dissect(pkt_data))
    assert Wifi80211Frame.FC_TypeSubtype[f] == 0x88
    body = Wifi80211Frame.body.get_choice(f)
    assert isinstance(body, QoSDataBody)
    assert QoSDataBody.Duration[body] == 60
    assert QoSDataBody.Frame_Body[body].byte_length() == 1116  # payload after QoS header

    # Packet 25: Block Ack Request
    pkt_data = PacketRecord.Packet_Data[records[24]]
    f = Wifi80211Frame(Frames.dissect(pkt_data))
    assert Wifi80211Frame.FC_TypeSubtype[f] == 0x94
    body = Wifi80211Frame.body.get_choice(f)
    assert isinstance(body, BlockAckReqBody)
    assert BlockAckReqBody.Starting_Sequence_Number[body] == 0x0780
