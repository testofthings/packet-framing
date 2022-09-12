from framing.base import Structure
from framing.frames import BaseFrame


class EthernetII(BaseFrame['EthetnetII']):
    struct_ = Structure['EthernetII']()

    destination = struct_.raw_field(bytes=6)
    source = struct_.raw_field(bytes=6)
    type = struct_.int_field(bytes=2)
    data = struct_.raw_field()
    crc_checksum = struct_.raw_field(bytes=4)
    padding = struct_.raw_field()


