import pytest
from framing.backends import BackendImplementation, RawFrame
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

    s_field = Sequence(LVField(structure.raw(), IntegerFormat(bytes=2))).terminator_test(lambda r: not r)


class DFrame(Frame):
    structure = Structure['DFrame']()

    asciiz = structure.raw().terminator(Raw.octets(0))


class EFrame(Frame):
    structure = Structure['EFrame']()

    s_field = structure.raw(min_bytes=4, bytes=8)


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
    v = CFrame.s_field[c_frame]
    assert v == [Raw.hex("010203"), Raw.empty]
    assert CFrame.s_field.get_bit_length(c_frame) == 7 * 8


def test_terminator():
    d_frame = DFrame(Frames.compose())
    DFrame.asciiz[d_frame] = Raw.string("abc")
    d = d_frame.encode()
    assert d == Raw.hex("616263")  # NOTE: Does *not* add the end-zero - would require new field class!

    d_frame = DFrame(Frames.dissect(Raw.hex("61626300 6465")))
    assert DFrame.asciiz[d_frame] == Raw.hex("61626300")

def test_min_length():
    e_frame = EFrame(Frames.compose())
    c = e_frame.encode()
    assert c == Raw.hex("00000000")

    e_frame = EFrame(Frames.dissect(Raw.hex("00010203040506070809")))
    c = e_frame.byte_length() == 8  # max length

    e_frame = EFrame(Frames.dissect(Raw.hex("00010203040506070809")))
    d = EFrame.s_field[e_frame]
    assert d == Raw.hex("0001020304050607")

    e_frame = EFrame(Frames.dissect(Raw.hex("00010203040506070809")))
    d = EFrame.s_field.as_frame(e_frame, frame_type=RawFrame.build_with_lengths(min_bytes=4, bytes=7))
    assert isinstance(d, Frame)
    assert d.byte_length() == 7

    e_frame = EFrame(Frames.dissect(Raw.hex("00010203040506070809")))
    d = EFrame.s_field.as_frame(e_frame, frame_type=RawFrame)
    assert isinstance(d, Frame)
    assert d.byte_length() == 8

    e_frame = EFrame(Frames.dissect(Raw.hex("000102")))
    # pytest that exception thrown
    with pytest.raises(EOFError):
        c = e_frame.byte_length() == 8

    with pytest.raises(EOFError):
        d = EFrame.s_field[e_frame]

