from framing.base import Frame, Structure


class EthernetII(Frame['EthetnetII']):
    struct_ = Structure['EthernetII']()

    destination = struct_.raw_field(bytes=6)
    source = struct_.raw_field(bytes=6)
    type = struct_.int_field(bytes=2)
    data = struct_.raw_field()
    crc_checksum = struct_.raw_field(bytes=4)
    padding = struct_.raw_field()


