from framing.backends import BackendImplementation
from framing.base import Frame
from framing.codecs import IntegerCodec, IntegerFormat
from framing.fields import Structure, LVField, Sequence
from framing.frames import Frames
from framing.raw_data import Raw


class AFrame(Frame):
    structure = Structure['AFrame']()

    lv_field = LVField(structure.raw(), IntegerFormat(bytes=2))


class BFrame(Frame):
    structure = Structure['BFrame']()

    s_field = Sequence(LVField(structure.raw(), IntegerFormat(bytes=2)))


class CFrame(Frame):
    structure = Structure['CFrame']()

    s_field = Sequence(LVField(structure.raw(), IntegerFormat(bytes=2))).terminate_by(Raw.empty)


def test_lv_compose():
    a_frame = AFrame(Frames.compose())
    AFrame.lv_field[a_frame] = Raw.hex("010203")

    b = a_frame.encode()
    assert b == Raw.hex("0003 010203")

    assert BackendImplementation.list_resolved_fields(a_frame) == [AFrame.lv_field]
    assert AFrame.lv_field.get_bit_length(a_frame) == 5 * 8


def test_lv_dissect():
    a_frame = AFrame(Frames.dissect(Raw.hex("0002 0102030405")))

    v = AFrame.lv_field[a_frame]
    assert v == Raw.hex("0102")
    assert AFrame.lv_field.get_bit_length(a_frame) == 4 * 8


def test_seq_lv_compose():
    a_frame = BFrame(Frames.compose())

    BFrame.s_field[a_frame] = [Raw.hex("010203"), Raw.empty, Raw.hex("04")]

    b = a_frame.encode()
    assert b == Raw.hex("0003 010203 0000 0001 04")
    assert BFrame.s_field.get_bit_length(a_frame) == 10 * 8


def test_seq_lv_dissect():
    a_frame = BFrame(Frames.dissect(Raw.hex("0003 010203 0000 0001 04")))

    v = BFrame.s_field[a_frame]
    assert v == [Raw.hex("010203"), Raw.empty, Raw.hex("04")]
    assert BFrame.s_field.get_bit_length(a_frame) == 10 * 8

    c_frame = CFrame(Frames.dissect(Raw.hex("0003 010203 0000 0001 04")))
    v = CFrame.s_field[a_frame]
    assert v == [Raw.hex("010203")]
    assert CFrame.s_field.get_bit_length(a_frame) == 7 * 8
