"""IEEE 802.11 MAC frame definitions

Supports CTS, Block Ack Request, Data/Null, and QoS Data frame types.
Reference: IEEE 802.11-2020 (https://standards.ieee.org/ieee/802.11/7028/)
"""

import enum

from framing.base import Frame, LayerMapping
from framing.codecs import IntegerFormat
from framing.fields import Selection, Structure

# pylint: disable=invalid-name

# Little-endian integers: 802.11 uses little-endian byte order for multi-byte fields
LE = IntegerFormat().big_endian()


class CTSBody(Frame):
    """CTS (Clear to Send) control frame body — fields after Frame Control"""
    structure = Structure['CTSBody']()

    Duration = structure.integer(LE.bytes(2))
    RA       = structure.raw(bytes=6)


class BlockAckReqBody(Frame):
    """Block Ack Request control frame body — fields after Frame Control"""
    structure = Structure['BlockAckReqBody']()

    Duration                 = structure.integer(LE.bytes(2))
    RA                       = structure.raw(bytes=6)
    TA                       = structure.raw(bytes=6)
    BAR_Information          = structure.integer(LE.bytes(2))
    Starting_Sequence_Number = structure.integer(LE.bytes(2))
    BAR_Bitmap               = structure.raw(bytes=8)


class DataNullBody(Frame):
    """Data / Null frame body — fields after Frame Control"""
    structure = Structure['DataNullBody']()

    Duration         = structure.integer(LE.bytes(2))
    Addr1            = structure.raw(bytes=6)
    Addr2            = structure.raw(bytes=6)
    Addr3            = structure.raw(bytes=6)
    Sequence_Control = structure.integer(LE.bytes(2))


class QoSDataBody(Frame):
    """QoS Data frame body — fields after Frame Control"""
    structure = Structure['QoSDataBody']()

    Duration         = structure.integer(LE.bytes(2))
    Addr1            = structure.raw(bytes=6)
    Addr2            = structure.raw(bytes=6)
    Addr3            = structure.raw(bytes=6)
    Sequence_Control = structure.integer(LE.bytes(2))
    QoS_Control      = structure.integer(LE.bytes(2))
    Frame_Body       = structure.raw()


class Wifi80211Body(Frame):
    """802.11 MAC frame body, dispatched by Frame Control byte 0 (FC_TypeSubtype)

    Key = FC byte 0 value, encodes Subtype[7:4] Type[3:2] ProtocolVersion[1:0].
    Known keys:
      0xD4 = CTS          (Type=1 Control, Subtype=13)
      0x94 = Block Ack Req (Type=1 Control, Subtype=9)
      0x48 = Null          (Type=2 Data, Subtype=4)
      0x88 = QoS Data      (Type=2 Data, Subtype=8)
    """
    structure = Selection['Wifi80211Body']()

    cts       = structure.choice(0xD4, structure.sub(CTSBody))
    bar_req   = structure.choice(0x94, structure.sub(BlockAckReqBody))
    null_data = structure.choice(0x48, structure.sub(DataNullBody))
    qos_data  = structure.choice(0x88, structure.sub(QoSDataBody))
    unknown   = structure.raw()


class Wifi80211Frame(Frame):
    """IEEE 802.11 MAC frame

    Frame Control byte layout:
      Byte 0 (FC_TypeSubtype): Subtype[7:4]  Type[3:2]  ProtocolVersion[1:0]
      Byte 1 (FC_Flags):       Order[7]  ProtectedFrame[6]  MoreData[5]
                               PowerMgmt[4]  Retry[3]  MoreFrags[2]
                               FromDS[1]  ToDS[0]
    """
    structure = Structure['Wifi80211Frame']()

    FC_TypeSubtype = structure.integer(bits=8)   # Frame Control byte 0
    FC_Flags       = structure.integer(bits=8)   # Frame Control byte 1
    body           = structure.sub(Wifi80211Body).choice_by(FC_TypeSubtype)


class Wifi80211FCFlags(enum.IntFlag):
    """Frame Control flags (FC byte 1 bit definitions)"""
    To_DS           = 0x01
    From_DS         = 0x02
    More_Fragments  = 0x04
    Retry           = 0x08
    Power_Management = 0x10
    More_Data       = 0x20
    Protected_Frame = 0x40
    Order           = 0x80


Wifi80211Frame.FC_Flags.flag_values(Wifi80211FCFlags)


# PCAP payload mapping: LinkType 105 = IEEE 802.11 without radio header
from framing.frame_types.pcap_frames import FileHeader, PacketRecord, PCAPFile  # noqa: E402

Wifi80211_PCAP_Payloads = LayerMapping(PacketRecord.Packet_Data).by(
    PCAPFile.File_Header / FileHeader.LinkType,
    {105: Wifi80211Frame},
)
