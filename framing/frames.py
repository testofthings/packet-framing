from typing import Callable, cast

from framing.backends import ComposingBackend, FrameBackend, DissectorBackend, BackendImplementation
from framing.base import Frame, LayerMapping
from framing.raw_data import RawData


class Frames:
    @classmethod
    def compose(cls) -> Callable[['Frame'], FrameBackend]:
        """Create new frame for composing"""
        return lambda f: ComposingBackend(f, LayerMapping())

    @classmethod
    def dissect(cls, data: RawData) -> Callable[['Frame'], FrameBackend]:
        return lambda f: DissectorBackend(f, LayerMapping(), data)

    @classmethod
    def dump(cls, frame: Frame, bit_offset=80, indent='', width=0, copy_to_avoid_update=False) -> str:
        be = cast(BackendImplementation, frame.backend)
        if copy_to_avoid_update:
            be = be.copy()
        return be.dump(bit_offset, indent, width, copy_to_avoid_update)


