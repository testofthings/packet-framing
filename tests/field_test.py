from framing.base import Frame
from framing.codecs import IntegerCodec, IntegerFormat
from framing.fields import Structure, LVField
from framing.frames import Frames
from framing.raw_data import Raw


class AFrame(Frame):
    structure = Structure['AFrame']()

    lv_field = LVField(structure.raw(), IntegerFormat(bytes=2))


def test_lv_compose():
    a_frame = AFrame(Frames.compose())
    AFrame.lv_field[a_frame] = Raw.hex("010203")

    b = a_frame.encode()
    assert b == Raw.hex("0003 010203")


def test_lv_dissect():
    a_frame = AFrame(Frames.dissect(Raw.hex("0002 0102030405")))

    v = AFrame.lv_field[a_frame]
    assert v == Raw.hex("0102")
