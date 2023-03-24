import pathlib
from typing import Callable, cast, Type, Dict, Any, TypeVar, Optional

from framing.backends import ComposingBackend, FrameBackend, DissectorBackend, BackendImplementation
from framing.base import Frame, LayerMapping, F
from framing.raw_data import RawData, Raw

V = TypeVar("V")


class Frames:
    @classmethod
    def compose(cls) -> Callable[['Frame'], FrameBackend]:
        """Create new frame for composing"""
        return lambda f: ComposingBackend(f, LayerMapping())

    @classmethod
    def dissect(cls, data: RawData, mappings=LayerMapping()) -> Callable[['Frame'], FrameBackend]:
        return lambda f: DissectorBackend(f, mappings, data)

    @classmethod
    def dissect_file(cls, file: pathlib.Path) -> Callable[['Frame'], FrameBackend]:
        data = Raw.file(file)
        return lambda f: DissectorBackend(f, LayerMapping(), data)

    @classmethod
    def process(cls, frame: F, procedures: Dict[Type[Frame], Callable[[Any], V]]) -> Optional[V]:
        """Process frame here differentiating by frame type"""
        proc = procedures.get(type(frame))
        if not proc:
            proc = procedures.get(Frame)  # fallback
        return proc(frame) if proc else None

    @classmethod
    def close(cls, frame: F) -> F:
        """Close underlying open files if any"""
        frame.backend.close()
        return frame

    @classmethod
    def dump(cls, frame: Frame, bit_offset=80, indent='', width=0, copy_to_avoid_update=False) -> str:
        be = cast(BackendImplementation, frame.backend)
        if copy_to_avoid_update:
            be = be.copy()
        return be.dump(bit_offset, indent, width, copy_to_avoid_update)


