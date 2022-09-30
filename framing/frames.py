from typing import Callable, Type, List

from framing.backends import ComposingBackend, F, FrameBackend, DissectorBackend
from framing.base import Frame, F
from framing.fields import Structure
from framing.raw_data import RawData


class Frames:
    @classmethod
    def compose(cls) -> Callable[['Frame'], FrameBackend]:
        """Create new frame for composing"""
        return lambda f: ComposingBackend(f)

    @classmethod
    def dissect(cls, data: RawData) -> Callable[['Frame'], FrameBackend]:
        return lambda f: DissectorBackend(f, data)

    @classmethod
    def dump(cls, frame: Frame, bit_offset=80, indent='', width=0, copy_to_avoid_update=False) -> str:
        return frame.backend.dump(bit_offset, indent, width, copy_to_avoid_update)


