from framing.data_queue import RawDataQueue
from framing.raw_data import Raw


def test_data_queue():
    q = RawDataQueue(Raw.empty)

    q.push(Raw.octets(0), 0)
    assert q.head == Raw.octets(00)

    q.push(Raw.octets(2), 0)
    assert q.head == Raw.octets(00)

    q.push(Raw.octets(1), 1)
    assert q.head == Raw.octets(0, 1)

    q.push(Raw.octets(3, 4), 3)
    assert q.head == Raw.octets(0, 1)

    q.push(Raw.octets(2), 2)
    assert q.head == Raw.octets(0, 1, 2, 3, 4)

    q.push(Raw.octets(10, 11, 12, 13), 10)
    assert q.head == Raw.octets(0, 1, 2, 3, 4)

    q.push(Raw.octets(5, 6, 7, 8, 9, 20), 5)
    assert q.head == Raw.octets(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 20, 11, 12, 13)
    assert q.offset == 0

    r = q.pull(10)
    assert q.offset == 10
    assert r == Raw.octets(0, 1, 2, 3, 4, 5, 6, 7, 8, 9)
    assert q.head == Raw.octets(20, 11, 12, 13)


def test_data_queue_modulus():
    q = RawDataQueue(Raw.empty, offset=95)
    q.modulus = 100

    q.push(Raw.octets(0, 1, 2, 3, 4, 5), 95)
    q.push(Raw.octets(7), 2)
    r = q.pull(3)
    assert q.offset == 98
    assert r == Raw.octets(0, 1, 2)
    assert q.head == Raw.octets(3, 4, 5)

    q.push(Raw.octets(6), 1)
    assert q.head == Raw.octets(3, 4, 5, 6, 7)

    r = q.pull(4)
    assert q.offset == 2
    assert r == Raw.octets(3, 4, 5, 6)
    assert q.head == Raw.octets(7)

