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

    def update_padding(self):
        return Raw.zeroes(max(64 - (14 + self.data.get_byte_length(self) + 4), 0))

    padding.at_commit(update_padding)
