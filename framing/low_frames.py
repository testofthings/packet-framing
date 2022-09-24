from framing.base import Structure, Frame
from framing.raw_data import Raw


class EthernetII(Frame):
    structure = Structure['EthernetII']()

    destination = structure.raw(bytes=6)
    source = structure.raw(bytes=6)
    type = structure.integer(bytes=2)
    data = structure.raw()
    crc_checksum = structure.raw(bytes=4)
    padding = structure.raw()

    def update_padding(self):
        return Raw.zeroes(max(64 - (14 + EthernetII.data.get_byte_length(self) + 4), 0))

    padding.at_commit(update_padding)
