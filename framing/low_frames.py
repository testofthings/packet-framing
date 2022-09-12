from framing.base import Structure
from framing.frames import BaseFrame
from framing.raw_data import Raw


class EthernetII(BaseFrame['EthetnetII']):
    fields = Structure['EthernetII']()

    destination = fields.raw(bytes=6)
    source = fields.raw(bytes=6)
    type = fields.integer(bytes=2)
    data = fields.raw()
    crc_checksum = fields.raw(bytes=4)
    padding = fields.raw()

    def add_padding(self):
        d_len = 14 + EthernetII.data.get_byte_length(self) + 4
        pad_len = max(64 - d_len, 0)
        EthernetII.padding.set(self, Raw.zeroes(pad_len))

    fields.at_commit(add_padding)
