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

class TLSChangeCipherSpec(Frame):
    structure = Structure['TLSChangeCipherSpec']()

    message = structure.integer(bits=8)


class TLSAlert(Frame):
    structure = Structure['TLSAlert']()

    level = structure.integer(bits=8)
    description = structure.integer(bits=8)


class TLSApplicationData(Frame):
    structure = Structure['TLSApplicationData']()

    data = structure.raw()


# TLS record content mappings
TLSRecord_Payloads = LayerMapping(TLSRecord.fragment).by(TLSRecord.ContentType, {
    22: TLSHandshake,
    20: TLSChangeCipherSpec,
    21: TLSAlert,
    23: TLSApplicationData,
})
