import pathlib

from framing.backends import RawFrame
from framing.command import StackBuilder
from framing.frame_types.ipv4_frames import IPv4, IP_Payloads
from framing.frame_types.llc_frames import LLC, LLC_Payloads
from framing.frame_types.pcap_frames import PCAPFile, PCAP_Payloads, PacketRecord, PCAPRecordIterator
from framing.frame_types.udp_frames import UDP
from framing.frame_types.wifi_frames import (
    ACK, BLOCK_ACK, DATA, NULL, QOS_DATA, TYPE_CONTROL, TYPE_DATA, TYPE_MANAGEMENT,
    ACKFrame, BlockAckFrame, DataFrame, FrameControlFlag, MACFrame, MACFrameBody, NullFrame,
    QoSDataFrame, WiFi_Payloads, carries_payload, fragment_number, sequence_number, type_subtype,
)
from framing.frames import Frames
from framing.layer_stack import StackState
from framing.raw_data import Raw

WIFI_STACK = PCAP_Payloads + WiFi_Payloads + LLC_Payloads + IP_Payloads

# A QoS Data frame carrying LLC/SNAP, the frame body cut short
QOS_DATA_FRAME = Raw.hex("88 02"                # Frame Control: QoS Data, From DS
                         "3c 00"                # Duration/ID
                         "f6 e3 d1 31 ab 85"    # Address 1
                         "b4 c2 e0 2b 6d 09"    # Address 2
                         "b4 c2 e0 2b 6d 09"    # Address 3
                         "60 79"                # Sequence Control
                         "00 00"                # QoS Control
                         "aa aa 03 00 00 00 08 00 45 00")  # frame body


def test_type_subtype_values():
    # the combined value is the first octet of a frame shifted right by the Protocol Version bits
    assert type_subtype(TYPE_CONTROL, 13) == ACK == 0xd4 >> 2
    assert type_subtype(TYPE_CONTROL, 9) == BLOCK_ACK == 0x94 >> 2
    assert type_subtype(TYPE_DATA, 0) == DATA == 0x08 >> 2
    assert type_subtype(TYPE_DATA, 4) == NULL == 0x48 >> 2
    assert type_subtype(TYPE_DATA, 8) == QOS_DATA == 0x88 >> 2


def test_ack_frame():
    data = Raw.hex("d4 00 00 00 f6 e3 d1 31 ab 85")
    f = MACFrame(Frames.dissect(data))

    assert MACFrame.Type_Subtype[f] == ACK
    assert MACFrame.Protocol_Version[f] == 0
    assert MACFrame.Flags[f] == 0
    assert MACFrame.Duration_ID[f] == 0

    ack = MACFrame.Body.get_choice(f)
    assert isinstance(ack, ACKFrame)
    assert ACKFrame.RA[ack] == Raw.hex("f6 e3 d1 31 ab 85")
    assert f.byte_length() == data.byte_length()


def test_null_frame():
    data = Raw.hex("48 11 6c 00 b4 c2 e0 2b 6d 09 f6 e3 d1 31 ab 85 b4 c2 e0 2b 6d 09 80 02")
    f = MACFrame(Frames.dissect(data))

    assert MACFrame.Type_Subtype[f] == NULL
    assert MACFrame.Flags[f] == FrameControlFlag.TO_DS | FrameControlFlag.POWER_MANAGEMENT
    assert MACFrame.Duration_ID[f] == 108

    null = MACFrame.Body.get_choice(f)
    assert isinstance(null, NullFrame)
    assert NullFrame.Address_1[null] == Raw.hex("b4 c2 e0 2b 6d 09")
    assert NullFrame.Address_2[null] == Raw.hex("f6 e3 d1 31 ab 85")
    assert NullFrame.Address_3[null] == Raw.hex("b4 c2 e0 2b 6d 09")
    assert sequence_number(NullFrame.Sequence_Control[null]) == 40
    assert fragment_number(NullFrame.Sequence_Control[null]) == 0
    assert f.byte_length() == data.byte_length()


def test_block_ack_frame():
    data = Raw.hex("94 00 00 00 f6 e3 d1 31 ab 85 b4 c2 e0 2b 6d 09 04 00 80 07"
                   "ff ff ff ff ff ff ff ff")
    f = MACFrame(Frames.dissect(data))

    assert MACFrame.Type_Subtype[f] == BLOCK_ACK
    assert MACFrame.Duration_ID[f] == 0

    ba = MACFrame.Body.get_choice(f)
    assert isinstance(ba, BlockAckFrame)
    assert BlockAckFrame.RA[ba] == Raw.hex("f6 e3 d1 31 ab 85")
    assert BlockAckFrame.TA[ba] == Raw.hex("b4 c2 e0 2b 6d 09")
    assert BlockAckFrame.BA_Control[ba] == 0x0004
    assert BlockAckFrame.Block_Ack_Starting_Sequence_Control[ba] == 0x0780
    assert BlockAckFrame.Block_Ack_Bitmap[ba] == Raw.hex("ff ff ff ff ff ff ff ff")
    assert f.byte_length() == data.byte_length()


def test_qos_data_frame():
    f = MACFrame(Frames.dissect(QOS_DATA_FRAME, mappings=WiFi_Payloads))

    assert MACFrame.Type_Subtype[f] == QOS_DATA
    assert MACFrame.Flags[f] == FrameControlFlag.FROM_DS
    assert MACFrame.Duration_ID[f] == 60
    assert carries_payload(f)

    qos = MACFrame.Body.get_choice(f)
    assert isinstance(qos, QoSDataFrame)
    assert QoSDataFrame.Address_1[qos] == Raw.hex("f6 e3 d1 31 ab 85")
    assert QoSDataFrame.Address_2[qos] == Raw.hex("b4 c2 e0 2b 6d 09")
    assert QoSDataFrame.Address_3[qos] == Raw.hex("b4 c2 e0 2b 6d 09")
    assert sequence_number(QoSDataFrame.Sequence_Control[qos]) == 1942
    assert fragment_number(QoSDataFrame.Sequence_Control[qos]) == 0
    assert QoSDataFrame.QoS_Control[qos] == 0
    assert f.byte_length() == QOS_DATA_FRAME.byte_length()

    # the frame body is dissected as LLC
    llc = qos / QoSDataFrame.Frame_Body
    assert isinstance(llc, LLC)
    assert LLC.Type[llc] == 0x0800
    assert LLC.Data[llc] == Raw.hex("45 00")


def test_data_frame():
    data = Raw.hex("08 01"                # Frame Control: Data, To DS
                   "2c 00"                # Duration/ID
                   "b4 c2 e0 2b 6d 09"    # Address 1
                   "f6 e3 d1 31 ab 85"    # Address 2
                   "b4 c2 e0 2b 6d 09"    # Address 3
                   "10 00"                # Sequence Control
                   "aa aa 03 00 00 00 86 dd 60 00")  # frame body
    f = MACFrame(Frames.dissect(data, mappings=WiFi_Payloads))

    assert MACFrame.Type_Subtype[f] == DATA
    assert MACFrame.Flags[f] == FrameControlFlag.TO_DS
    assert MACFrame.Duration_ID[f] == 44

    frame = MACFrame.Body.get_choice(f)
    assert isinstance(frame, DataFrame)
    assert DataFrame.Address_1[frame] == Raw.hex("b4 c2 e0 2b 6d 09")
    assert sequence_number(DataFrame.Sequence_Control[frame]) == 1
    assert fragment_number(DataFrame.Sequence_Control[frame]) == 0
    assert f.byte_length() == data.byte_length()

    llc = frame / DataFrame.Frame_Body
    assert isinstance(llc, LLC)
    assert LLC.Type[llc] == 0x86dd
    assert LLC.Data[llc] == Raw.hex("60 00")


def test_protected_frame_body_stays_raw():
    # the same frame with the Protected Frame flag set, the frame body is encrypted
    protected = Raw.hex("88 42") + QOS_DATA_FRAME.tail_bytes(2)
    f = MACFrame(Frames.dissect(protected, mappings=WiFi_Payloads))

    assert MACFrame.Type_Subtype[f] == QOS_DATA
    assert MACFrame.Flags[f] == FrameControlFlag.FROM_DS | FrameControlFlag.PROTECTED_FRAME
    assert not carries_payload(f)

    qos = MACFrame.Body.get_choice(f)
    assert isinstance(qos, QoSDataFrame)
    assert isinstance(qos / QoSDataFrame.Frame_Body, RawFrame)
    assert QoSDataFrame.Frame_Body[qos] == Raw.hex("aa aa 03 00 00 00 08 00 45 00")


def test_unmodeled_frame_stays_raw():
    # a Beacon frame, management frames are not modeled
    data = Raw.hex("80 00 00 00 ff ff ff ff ff ff b4 c2 e0 2b 6d 09 b4 c2 e0 2b 6d 09 10 00 01 02")
    f = MACFrame(Frames.dissect(data))

    assert MACFrame.Type_Subtype[f] == type_subtype(TYPE_MANAGEMENT, 8)
    assert MACFrame.Body[f].backend.choice == MACFrameBody.Other
    assert MACFrame.Body.get_choice(f) == data.tail_bytes(4)
    assert f.byte_length() == data.byte_length()


def test_wifi_pcap():
    pcap = PCAPFile.open_file(pathlib.Path("samples/wifi_801_11.pcap"), mappings=WIFI_STACK)

    frames = {}
    for rec in PCAPRecordIterator(pcap):
        mac = rec / PacketRecord.Packet_Data
        assert isinstance(mac, MACFrame)
        body = MACFrame.Body.get_choice(mac)
        frames[type(body)] = frames.get(type(body), 0) + 1
        assert mac.byte_length() == PacketRecord.Captured_Packet_length[rec]

    assert frames == {ACKFrame: 17, BlockAckFrame: 1, NullFrame: 5, QoSDataFrame: 24}

    # frame 8 is a QoS Data frame carrying UDP over LLC/SNAP and IPv4
    mac = PCAPFile.Packet_Records.item(pcap, 8) / PacketRecord.Packet_Data
    assert MACFrame.Type_Subtype[mac] == QOS_DATA
    assert MACFrame.Duration_ID[mac] == 60

    qos = MACFrame.Body.get_choice(mac)
    assert QoSDataFrame.Address_1[qos] == Raw.hex("f6 e3 d1 31 ab 85")
    assert QoSDataFrame.Address_2[qos] == Raw.hex("b4 c2 e0 2b 6d 09")
    assert sequence_number(QoSDataFrame.Sequence_Control[qos]) == 1942

    llc = qos / QoSDataFrame.Frame_Body
    assert LLC.Type[llc] == 0x0800

    ip = llc / LLC.Data
    assert IPv4.Source_IP[ip] == Raw.hex("c0 a8 a9 01")
    assert IPv4.Destination_IP[ip] == Raw.hex("c0 a8 a9 02")
    assert IPv4.Protocol[ip] == 0x11

    udp = ip / IPv4.Payload
    assert UDP.Source_port[udp] == 1234
    assert UDP.Destination_port[udp] == 36175
    assert UDP.Length[udp] == 1088
    assert UDP.Data[udp].byte_length() == 1080

    Frames.close(pcap)


def test_wifi_encode():
    mac = MACFrame(Frames.compose())
    MACFrame.Duration_ID[mac] = 60
    MACFrame.Flags[mac] = FrameControlFlag.FROM_DS

    MACFrame.Body.select(mac, MACFrameBody.QoS_Data)
    qos = MACFrameBody.QoS_Data[MACFrame.Body[mac]]
    QoSDataFrame.Address_1[qos] = Raw.hex("f6 e3 d1 31 ab 85")
    QoSDataFrame.Address_2[qos] = Raw.hex("b4 c2 e0 2b 6d 09")
    QoSDataFrame.Address_3[qos] = Raw.hex("b4 c2 e0 2b 6d 09")
    QoSDataFrame.Sequence_Control[qos] = 1942 << 4
    QoSDataFrame.Frame_Body[qos] = Raw.hex("aa aa 03 00 00 00 08 00 45 00")

    # the Type and Subtype are pushed to Frame Control by the choice
    encoded = mac.encode()
    assert encoded == QOS_DATA_FRAME

    f = MACFrame(Frames.dissect(encoded))
    assert MACFrame.Type_Subtype[f] == QOS_DATA
    assert MACFrame.Duration_ID[f] == 60
    assert MACFrame.Flags[f] == FrameControlFlag.FROM_DS
    assert isinstance(MACFrame.Body.get_choice(f), QoSDataFrame)


def test_wifi_frame_stack():
    stack = StackBuilder.build_stack({})
    data = Raw.file(pathlib.Path("samples/wifi_801_11.pcap"))
    try:
        layers = [state.get_layer_names() for state in stack.receive(StackState(data))]
    finally:
        data.close()

    assert len(layers) == 47
    # the frames without a frame body stop at the MAC frame
    assert layers.count("PCAPFile / PacketRecord / 105=MACFrame") == 23
    assert layers.count(f"PCAPFile / PacketRecord / 105=MACFrame / {QOS_DATA}=LLC / 2048=IPv4 / 17=UDP") == 24
