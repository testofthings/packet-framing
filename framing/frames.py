from framing.backends import ComposingBackend, F, FrameBackend, DissectorBackend
from framing.base import Frame
from framing.raw_data import RawData


class Frames:
    @classmethod
    def compose(cls, frame_type: F) -> Frame[F]:
        """Create new frame for composing"""
        def factory(frame):
            return ComposingBackend(frame_type, frame)
        return Frame(frame_type, factory)

    @classmethod
    def dissect(cls, frame_type: F, data: RawData) -> Frame[F]:
        def factory(frame):
            return DissectorBackend(frame_type, frame, data)
        return Frame(frame_type, factory)
