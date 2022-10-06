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


def test_lv_compose():
    a_frame = AFrame(Frames.compose())
    AFrame.lv_field[a_frame] = Raw.hex("010203")

    b = a_frame.encode()
    assert b == Raw.hex("0003 010203")


def test_lv_dissect():
    a_frame = AFrame(Frames.dissect(Raw.hex("0002 0102030405")))

    v = AFrame.lv_field[a_frame]
    assert v == Raw.hex("0102")


def test_seq_lv_compose():
    a_frame = BFrame(Frames.compose())

    BFrame.s_field[a_frame] = [Raw.hex("010203"), Raw.empty, Raw.hex("04")]

    b = a_frame.encode()
    assert b == Raw.hex("0003 010203 0000 0001 04")


def test_seq_lv_dissect():
    a_frame = BFrame(Frames.dissect(Raw.hex("0003 010203 0000 0001 04")))

    v = BFrame.s_field[a_frame]
    assert v == [Raw.hex("010203"), Raw.empty, Raw.hex("04")]
