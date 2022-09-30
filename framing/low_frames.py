from framing.base import Frame
from framing.fields import Structure
from framing.codecs import IntegerFormat
from framing.raw_data import Raw


class EthernetII(Frame):
    structure = Structure['EthernetII']()

    destination = structure.raw(bytes=6)
    source = structure.raw(bytes=6)
    type = structure.integer(IntegerFormat(bytes=2))
    data = structure.raw()
    padding = structure.raw()
    crc_checksum = structure.raw(bytes=4)

    def update_padding(self):
        return Raw.zeroes(max(64 - (14 + EthernetII.data.get_byte_length(self) + 4), 0))

    padding.at_commit(update_padding)
