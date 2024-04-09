import io

import pytest
from framing.base import Frame
from framing.fields import Structure
from framing.frames import Frames
from framing.raw_data import AppendableRawData, Raw


def test_streams():
    for length in (0, 1, 2, 3, 4, 5, 6, 7, 16, 17, 255, 256, 257, 999, 111111):
        byte_array = bytearray((i % 256 for i in range(length)))
        byte_stream = io.BytesIO(byte_array)
        st = Raw.stream(byte_stream, name=f"test_{length}", request_size=211)
        assert st.bytes_available() == 0
        for i in range(length):
            assert st.octet(i) == byte_array[i]
        assert st.bytes_available() == length 

class AFrame(Frame):
    structure = Structure["AFrame"]()

    a_field = structure.raw(min_bytes=1, bytes=10)


def test_open_stream_decoding():
    data = AppendableRawData(Raw.hex("0102030405"))
    frame = AFrame(Frames.dissect(data))
    with pytest.raises(EOFError):
        frame.bit_length()  # stream open, cannot resolve length
    data.append(Raw.hex("060708090a0b0c0d0e0f"))
    assert frame.byte_length() == 10  # max length available, stream can be still open

    data = AppendableRawData(Raw.hex("0102030405"))
    frame = AFrame(Frames.dissect(data))
    with pytest.raises(EOFError):
        frame.bit_length()  # stream open, cannot resolve length
    data.append(Raw.hex("0607"))
    with pytest.raises(EOFError):
        frame.byte_length()  # stream open, cannot resolve length
    data.close()
    assert frame.byte_length() == 7  # stream closed
