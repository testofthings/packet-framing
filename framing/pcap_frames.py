from framing.base import *
from framing.frames import *

# https://datatracker.ietf.org/doc/id/draft-gharris-opsawg-pcap-00.html


class PCAP(Frame):
    structure = Structure['PCAP']()

    Magic_Number = structure.raw(bytes=4)
    Major_Version = structure.integer(bytes=2)
    Minor_Version = structure.integer(bytes=2)
    Reserved1 = structure.raw(bytes=4)
    Reserved2 = structure.raw(bytes=4)
    SnapLen = structure.integer(bytes=4)
    LinkType = structure.integer(bytes=4)
