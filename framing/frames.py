from framing.backends import EditableBackend, F, FrameBackend
from framing.base import Frame


class BaseFrame(Frame[F]):
    def __init__(self, frame_type: F, backend: FrameBackend = None):
        super().__init__(frame_type, backend or EditableBackend(frame_type, self))


class Frames:
    @classmethod
    def get_bit_length(cls, frame: Frame) -> int:
        """Get frame bit length"""
        st = frame.backend.structure
        return st.fields_length.get_offset(frame.backend)

    @classmethod
    def get_byte_length(cls, frame: Frame) -> int:
        """Get frame byte length"""
        st = frame.backend.structure
        return st.fields_length.get_offset(frame.backend) // 8
