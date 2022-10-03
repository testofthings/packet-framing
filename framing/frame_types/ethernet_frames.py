from framing.base import Frame, LayerMapping
from framing.fields import Structure
from framing.codecs import IntegerFormat
from framing.frame_types.ipv4_frames import IPv4
from framing.raw_data import Raw


class EthernetII(Frame):
    structure = Structure['EthernetII']()

    destination = structure.raw(bytes=6)
    source = structure.raw(bytes=6)
    type = structure.integer(IntegerFormat(bytes=2))
    data = structure.raw()
    padding = structure.raw().pad_to(min_offset=60)
    crc_checksum = structure.raw(bytes=4)

# Define Ethernet payload type mappings
Ethernet_Payloads = LayerMapping(EthernetII.data).by(EthernetII.type, {
    0x0800: IPv4,
})
