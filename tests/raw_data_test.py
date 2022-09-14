from framing.raw_data import Raw


def test_merged_data():
    b = Raw.merge([Raw.hex("01 02"), Raw.hex("03 04 05")])
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
