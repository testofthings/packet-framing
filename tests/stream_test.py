import io
from framing.raw_data import Raw


def test_streams():
    for length in (0, 1, 2, 3, 4, 5, 6, 7, 16, 17, 255, 256, 257, 999, 111111):
        byte_array = bytearray((i % 256 for i in range(length)))
        byte_stream = io.BytesIO(byte_array)
        st = Raw.stream(byte_stream, name=f"test_{length}", request_size=211)
        assert st.bytes_available() == 0
        for i in range(length):
            assert st.octet(i) == byte_array[i]
        assert st.bytes_available() == length 
