from framing.base import *
from framing.frames import *

# https://datatracker.ietf.org/doc/id/draft-gharris-opsawg-pcap-00.html


class PCAPType:
    def __init__(self):
        fields = Structure(PCAPType)
        self.fields = fields
        self.Magic_Number = fields.raw(bytes=4)
        self.Major_Version = fields.integer(bytes=2)
        self.Minor_Version = fields.integer(bytes=2)
        self.Reserved1 = fields.raw(bytes=4)
        self.Reserved2 = fields.raw(bytes=4)
        self.SnapLen = fields.integer(bytes=4)
        self.LinkType = fields.integer(bytes=4)


PCAP = PCAPType()





