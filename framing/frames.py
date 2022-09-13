from framing.base import Frame, S, FrameBackend
from framing.backends import EditableBackend


class BaseFrame(Frame[S]):
    def __init__(self, backend: FrameBackend = None):
        super().__init__(backend or EditableBackend(self))


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
