from framing.base import Structure, Frame
from framing.raw_data import Raw


class EthernetIIType:
    def __init__(self):
        fields = Structure(self)
        self.fields = fields
        self.destination = fields.raw(bytes=6)
        self.source = fields.raw(bytes=6)
        self.type = fields.integer(bytes=2)
        self.data = fields.raw()
        self.crc_checksum = fields.raw(bytes=4)
        self.padding = fields.raw()

        def update_padding(frame: Frame[EthernetIIType]):
            return Raw.zeroes(max(64 - (14 + self.data.get_byte_length(frame) + 4), 0))

        self.padding.at_commit(update_padding)


EthernetII = EthernetIIType()
