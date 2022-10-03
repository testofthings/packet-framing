from framing.frames import Frames
from framing.ipv4_frames import IPv4
from framing.raw_data import Raw


def test_ipv4():
    ip = IPv4(Frames.compose())
    ip_s = f"{ip}"

    ip.encode()
    assert IPv4.Version[ip] == 4
    assert IPv4.IHL[ip] == 5
    assert IPv4.Total_Length[ip] == 20
    assert IPv4.Options[ip] == Raw.empty
    assert IPv4.Payload[ip] == Raw.empty

