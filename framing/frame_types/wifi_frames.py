"""IEEE 802.11 (Wi-Fi) MAC frame definitions"""

import enum
from typing import Any, Dict, Iterable, Type

from framing.base import FieldPointer, Frame, LayerMapping
from framing.codecs import IntegerFormat
from framing.fields import FieldPath, IntField, RawField, Selection, Structure, ValueOf
from framing.frame_types.llc_frames import LLC
from framing.frames import Frames
from framing.layer_stack import StackLayer, StackState
from framing.raw_data import Raw

# IEEE Std 802.11-2020, clause 9.2 "MAC frame formats"

# pylint: disable=invalid-name

# 802.11 integers are least significant octet first, which this library calls big endian
LE = IntegerFormat().big_endian()

# Frame Control Type values, 9.2.4.1.3
TYPE_MANAGEMENT = 0
TYPE_CONTROL = 1
TYPE_DATA = 2
TYPE_EXTENSION = 3


def type_subtype(frame_type: int, subtype: int) -> int:
    """Combined Subtype and Type value, as they are in the first octet of Frame Control"""
    return (subtype << 2) | frame_type


# Combined Subtype and Type values of the modeled frames, 9.2.4.1.3
BLOCK_ACK = type_subtype(TYPE_CONTROL, 9)
ACK = type_subtype(TYPE_CONTROL, 13)
DATA = type_subtype(TYPE_DATA, 0)
NULL = type_subtype(TYPE_DATA, 4)
QOS_DATA = type_subtype(TYPE_DATA, 8)


class FrameControlFlag(enum.IntFlag):
    """Frame Control flag definitions, the second octet of the field, 9.2.4.1"""
    TO_DS = 0x01
    FROM_DS = 0x02
    MORE_FRAGMENTS = 0x04
    RETRY = 0x08
    POWER_MANAGEMENT = 0x10
    MORE_DATA = 0x20
    PROTECTED_FRAME = 0x40
    HTC_ORDER = 0x80


class ACKFrame(Frame):
    """ACK frame, 9.3.1.4"""
    structure = Structure['ACKFrame']()

    RA = structure.raw(bytes=6)


class BlockAckFrame(Frame):
    """BlockAck frame, 9.3.1.9, compressed BlockAck variant"""
    structure = Structure['BlockAckFrame']()

    RA = structure.raw(bytes=6)
    TA = structure.raw(bytes=6)
    BA_Control = structure.integer(LE.bytes(2))
    Block_Ack_Starting_Sequence_Control = structure.integer(LE.bytes(2))
    Block_Ack_Bitmap = structure.raw()


class DataFrame(Frame):
    """Data frame, 9.3.2.1, the three address variant"""
    structure = Structure['DataFrame']()

    Address_1 = structure.raw(bytes=6)
    Address_2 = structure.raw(bytes=6)
    Address_3 = structure.raw(bytes=6)
    Sequence_Control = structure.integer(LE.bytes(2))
    Frame_Body = structure.raw()


class QoSDataFrame(Frame):
    """QoS Data frame, 9.3.2.1, the three address variant"""
    structure = Structure['QoSDataFrame']()

    Address_1 = structure.raw(bytes=6)
    Address_2 = structure.raw(bytes=6)
    Address_3 = structure.raw(bytes=6)
    Sequence_Control = structure.integer(LE.bytes(2))
    QoS_Control = structure.integer(LE.bytes(2))
    Frame_Body = structure.raw()


class NullFrame(Frame):
    """Null frame, 9.3.2.1, a Data frame without a frame body"""
    structure = Structure['NullFrame']()

    Address_1 = structure.raw(bytes=6)
    Address_2 = structure.raw(bytes=6)
    Address_3 = structure.raw(bytes=6)
    Sequence_Control = structure.integer(LE.bytes(2))


class MACFrameBody(Frame):
    """The frame specific part of a MAC frame, by Type and Subtype"""
    structure = Selection['MACFrameBody']()

    Other = structure.raw()  # frame types which are not modeled, e.g. management frames
    Block_Ack = structure.choice(BLOCK_ACK, structure.sub(BlockAckFrame))
    ACK = structure.choice(ACK, structure.sub(ACKFrame))
    Data = structure.choice(DATA, structure.sub(DataFrame))
    Null = structure.choice(NULL, structure.sub(NullFrame))
    QoS_Data = structure.choice(QOS_DATA, structure.sub(QoSDataFrame))


class MACFrame(Frame):
    """802.11 MAC frame, 9.2.3. The FCS is assumed to be stripped off"""
    structure = Structure['MACFrame']()

    # Frame Control, 9.2.4.1, is modeled by the octet, as the frames are told apart by Type and
    # Subtype alone. The standard numbers the bits b0...b15, b0 being sent first, i.e. b0 is the
    # least significant bit of the first octet, thus the reverse order of the subfields here.
    Type_Subtype = structure.integer(bits=6)      # Subtype b4-b7 and Type b2-b3
    Protocol_Version = structure.integer(bits=2)  # b0-b1
    Flags = structure.integer(bits=8)             # b8-b15, see FrameControlFlag

    Duration_ID = structure.integer(LE.bytes(2))
    Body = structure.sub(MACFrameBody).choice_by(ValueOf(Type_Subtype))


MACFrame.Flags.flag_values(FrameControlFlag)


# The frame body field of the frames which carry a payload
_Frame_Bodies: Dict[Type[Frame], RawField[Any]] = {
    DataFrame: DataFrame.Frame_Body,
    QoSDataFrame: QoSDataFrame.Frame_Body,
}


def carries_payload(frame: MACFrame) -> bool:
    """Does the frame carry a payload which can be dissected?"""
    return not MACFrame.Flags[frame] & FrameControlFlag.PROTECTED_FRAME


class WiFiStackLayer(StackLayer):
    """802.11 MAC frame stack layer"""
    def __init__(self) -> None:
        super().__init__(MACFrame)

    def receive(self, state: StackState) -> Iterable[StackState]:
        frame = MACFrame(Frames.dissect(state.data))
        body = MACFrame.Body.get_choice(frame)
        field = _Frame_Bodies.get(type(body))  # only some frames carry a payload
        data = field.as_raw(body) if field and carries_payload(frame) else None
        # without payload the frame is the top frame, thus no payload type
        pay_type = MACFrame.Type_Subtype[frame] if data else None
        return [state.add(frame, pay_type, data or Raw.empty)]


def fragment_number(sequence_control: int) -> int:
    """Fragment Number of a Sequence Control value, 9.2.4.4.2"""
    return sequence_control & 0xf


def sequence_number(sequence_control: int) -> int:
    """Sequence Number of a Sequence Control value, 9.2.4.4.3"""
    return sequence_control >> 4


class FlagOf(FieldPointer[Frame, int]):
    """Pointer to a single flag of an integer field, e.g. of the Frame Control Flags"""
    def __init__(self, field: IntField[Any], flag: enum.IntFlag) -> None:
        self.path: FieldPath[int] = FieldPath(field)  # the field can be in a parent frame
        self.flag = int(flag)

    def get(self, frame: Frame) -> int:
        return self.path.get(frame) & self.flag


# The flag is in the MAC frame, which is the parent frame of a frame body
_Protection = FlagOf(MACFrame.Flags, FrameControlFlag.PROTECTED_FRAME)

# Define 802.11 payload type mappings, a protected frame body is encrypted and stays raw
WiFi_Payloads = LayerMapping(DataFrame.Frame_Body).many_by({
    DataFrame.Frame_Body: _Protection,
    QoSDataFrame.Frame_Body: _Protection,
}, {
    0: LLC,
})
