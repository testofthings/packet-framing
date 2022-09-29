from typing import Callable, Type, List

from framing.backends import ComposingBackend, F, FrameBackend, DissectorBackend
from framing.base import Frame, F
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
    def repeat(cls, context: Frame, sub_type: Type[F], count: int) -> List[F]:
        v = []
        factory = context.backend.factory()
        for _ in range(0, count):
            v.append(sub_type(factory))
        return v
