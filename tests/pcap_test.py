import pathlib

from framing.frames import Frames
from framing.pcap_frames import PCAP
from framing.raw_data import Raw


def test_pcap():
    b = Raw.file(pathlib.Path("samples/sample-1.pcap"))
    pcap = PCAP(Frames.dissect(b))
    assert PCAP.Magic_Number[pcap] == Raw.hex("D4C3B2A1")
    b.close()

