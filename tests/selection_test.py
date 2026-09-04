from framing.base import Frame
from framing.fields import Selection, Structure
from framing.frames import Frames
from framing.raw_data import Raw


class ASelection(Frame):
    structure = Selection['ASelection']()

    A = structure.choice(1, structure.integer(bytes=2))
    B = structure.choice(2, structure.raw(bytes=8))
    C = structure.choice(3, structure.integer(bytes=4))


class XFrame(Frame):
    structure = Structure['XFrame']()

    type = structure.integer(bytes=1)
    value = structure.sub(ASelection).choice_by(type)


def test_selection():
    x = XFrame(Frames.compose())

    b = XFrame.value.select(x, ASelection.B)
    assert b.byte_length() == 8
    assert b.encode() == Raw.hex("0000 0000 0000 0000")

    ASelection.C[b] = 0x1234
    assert b.encode() == Raw.hex("0000 1234")

    assert x.encode() == Raw.hex("03 0000 1234")


def test_selection_decode():
    x = XFrame(Frames.dissect(Raw.hex("03 0123 4567 89")))
    assert XFrame.type[x] == 3
    v = XFrame.value[x]
    assert v.encode() == Raw.hex("01234567")




def test_selection_encode_chosen_key():
    x = XFrame(Frames.compose())
    a = XFrame.value.select(x, ASelection.A)
    ASelection.A[a] = 0x0102

    # the key of the chosen alternative is stored, not the key of the last declared one
    assert x.encode() == Raw.hex("01 0102")
    assert XFrame.type[x] == 1
