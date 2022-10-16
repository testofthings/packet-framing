from framing.base import Frame, LayerMapping
from framing.codecs import IntegerFormat
from framing.fields import Structure, ValueOf
from framing.frame_types.dns_frames import DNSMessage


class UDP(Frame):
    structure = Structure['UDP']()

    Source_port = structure.integer(IntegerFormat(bits=16))
    Destination_port = structure.integer(IntegerFormat(bits=16))
    Length = structure.integer(IntegerFormat(bits=16))
    Checksum = structure.raw(bits=16)
    Data = structure.raw().end_offset_by(ValueOf(Length))


# Well-known UDP port mappings
UDP_Common_Payloads = LayerMapping(UDP.Data).by(UDP.Destination_port, {
    53: DNSMessage,
}).by(UDP.Source_port, {
    53: DNSMessage,
})
