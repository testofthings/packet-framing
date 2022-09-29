import pathlib

from framing.frames import Frames
from framing.pcap_frames import PCAPFile, FileHeader
from framing.raw_data import Raw


def test_pcap():
    pcap = PCAPFile(Frames.compose())
    as_str = f"{pcap}"
    pcap_hdr = PCAPFile.File_Header.get[pcap]


def test_pcap_decode():
    b = Raw.file(pathlib.Path("samples/sample-1.pcap"))
    pcap = PCAPFile(Frames.dissect(b))
    pcap_hdr = PCAPFile.File_Header.get[pcap]
    assert FileHeader.Magic_Number[pcap_hdr] == Raw.hex("D4C3B2A1")
    b.close()

