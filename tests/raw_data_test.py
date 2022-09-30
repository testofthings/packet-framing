import pathlib

from framing.raw_data import Raw


def test_merged_data():
    b = Raw.sequence([Raw.hex("01 02"), Raw.hex("03 04 05")])
    assert b.bit_length() == 5 * 8
    assert b.byte_length() == 5
    assert b == Raw.hex("01 02 03 04 05")
    assert b != Raw.hex("01 02 03 04 ff")

    b2 = b.tailBytes(1)
    assert b2 == Raw.hex("02 03 04 05")

    b2 = b.tailBytes(3)
    assert b2 == Raw.hex("04 05")

    b2 = b.tailBytes(10)
    assert b2 == Raw.empty


def test_file():
    b = Raw.file(pathlib.Path("samples/hello-world.txt"))
    assert b == Raw.hex("48 65 6c 6c 6f 2c 20 77 6f 72 6c 64 21 0a")
    assert b.byte_length() == 14
