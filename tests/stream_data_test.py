import io
from framing.raw_data import *

def test_bit_length():
    stream = io.BytesIO(b'\x01\x02\x03')
    data = StreamData(stream, "test_stream")
    assert data.bit_length() == 24

def test_byte_length():
    stream = io.BytesIO(b'\x01\x02\x03')
    data = StreamData(stream, "test_stream")
    assert data.byte_length() == 3

def test_bits_available():
    stream = io.BytesIO(b'\x01\x02\x03')
    data = StreamData(stream, "test_stream")
    assert data.bits_available() == 0
    b = data.octet(0)
    assert b == 1
    assert data.bits_available() == 24

def test_bytes_available():
    stream = io.BytesIO(b'\x01\x02\x03')
    data = StreamData(stream, "test_stream")
    assert data.bytes_available() == 0
    b = data.octet(0)
    assert b == 1
    assert data.bytes_available() == 3

def test_octet():
    stream = io.BytesIO(b'\x01\x02\x03')
    data = StreamData(stream, "test_stream")
    assert data.octet(1) == 2

def test_bit():
    stream = io.BytesIO(b'\x01\x82\x03')
    data = StreamData(stream, "test_stream")
    assert data.bit(8) == 1
    assert data.bytes_available() == 3

def test_subBlock():
    stream = io.BytesIO(b'\x01\x02\x03')
    data = StreamData(stream, "test_stream")
    sub_block = data.subBlock(1, 2)
    assert sub_block.byte_length() == 2
    assert sub_block.bytes_available() == 2

def test_tailBytes():
    stream = io.BytesIO(b'\x01\x02\x03')
    data = StreamData(stream, "test_stream")
    tail_bytes = data.tailBytes(1)
    assert tail_bytes.byte_length() == 2
    assert tail_bytes.bytes_available() == 2

def test_close():
    stream = io.BytesIO(b'\x01\x02\x03')
    data = StreamData(stream, "test_stream")
    data.close()
    assert data.buffer.closed
    assert data.stream.closed
