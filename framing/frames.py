from framing.backends import EditableBackend, F, FrameBackend
from framing.base import Frame


class Frames:
    @classmethod
    def compose(cls, frame_type: F) -> Frame[F]:
        """Create new frame for composing"""
        def factory(frame):
            return EditableBackend(frame_type, frame)
        return Frame(frame_type, factory)

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
