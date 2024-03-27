from framing.base import Frame, LayerMapping
from framing.fields import Structure, ValueOf
from framing.frame_processors import Processor


class TLSRecord(Frame):
    structure = Structure['TLSRecord']()

    ContentType = structure.integer(bits=8)
    ProtocolVersion = structure.integer(bits=16)
    length = structure.integer(bits=16)
    fragment = structure.raw().length_by(ValueOf(length))


class TLSHandshake(Frame):
    structure = Structure['TLSHandshake']()

    HandshakeType = structure.integer(bits=8)
    length = structure.integer(bits=24)
    message = structure.raw().length_by(ValueOf(length))


# TLS record content mappings
TLSRecord_Payloads = LayerMapping(TLSRecord.fragment).by(TLSRecord.ContentType, {
    22: TLSHandshake,
})
