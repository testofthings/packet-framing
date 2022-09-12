from framing.base import Structure
from framing.frames import BaseFrame
from framing.raw_data import Raw


class EthernetII(BaseFrame['EthetnetII']):
    struct_ = Structure['EthernetII']()

    destination = struct_.raw_field(bytes=6)
    source = struct_.raw_field(bytes=6)
    type = struct_.int_field(bytes=2)
    data = struct_.raw_field()
    crc_checksum = struct_.raw_field(bytes=4)
    padding = struct_.raw_field()

    def add_padding(self):
        d_len = 14 + EthernetII.data.get_byte_length(self) + 4
        pad_len = max(64 - d_len, 0)
        EthernetII.padding.set(self, Raw.zeroes(pad_len))

    struct_.at_commit(add_padding)
