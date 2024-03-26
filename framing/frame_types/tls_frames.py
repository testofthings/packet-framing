from framing.base import Frame
from framing.fields import Structure, ValueOf
from framing.frame_processors import Processor


class TLSRecord(Frame):
    structure = Structure['TLSRecord']()

    ContentType = structure.integer(bits=8)
    ProtocolVersion = structure.integer(bits=16)
    length = structure.integer(bits=16)
    fragment = structure.raw().length_by(ValueOf(length))
