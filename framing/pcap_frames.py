from framing.base import *
from framing.frames import *

# https://datatracker.ietf.org/doc/id/draft-gharris-opsawg-pcap-00.html


class PCAPFrame(Frame):
    fields = Structure['PCAPFrame']()


class PCAP:
    fields = PCAPFrame.fields
    Magic_Number = fields.raw(bytes=4)
    Major_Version = fields.integer(bytes=2)
    Minor_Version = fields.integer(bytes=2)
    Reserved1 = fields.raw(bytes=4)
    Reserved2 = fields.raw(bytes=4)
    SnapLen = fields.integer(bytes=4)
    LinkType = fields.integer(bytes=4)
