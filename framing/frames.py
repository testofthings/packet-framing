from typing import Callable

from framing.backends import ComposingBackend, F, FrameBackend, DissectorBackend
from framing.base import Frame
from framing.raw_data import RawData


class Frames:
    @classmethod
    def compose(cls) -> Callable[['Frame'], FrameBackend]:
        """Create new frame for composing"""
        return lambda f: ComposingBackend(f)

    @classmethod
    def dissect(cls, data: RawData) -> Callable[['Frame'], FrameBackend]:
        return lambda f: DissectorBackend(f, data)
