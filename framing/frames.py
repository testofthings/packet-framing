"""Frame utilities for processing and composing frames"""

import pathlib
from typing import Callable, cast, Type, Dict, Any, TypeVar, Optional

from framing.backends import ComposingBackend, FrameBackend, DissectorBackend, BackendImplementation
from framing.base import Frame, LayerMapping, F
from framing.data_queue import RawDataQueue
from framing.raw_data import RawData, Raw

F = TypeVar("F", bound=Frame)
V = TypeVar("V")


class Frames:
    """Frame processing utilities"""
    @classmethod
    def compose(cls) -> Callable[['Frame'], FrameBackend]:
        """Create new frame for composing"""
        return lambda f: ComposingBackend(f, LayerMapping())

    @classmethod
    def dissect(cls, data: RawData, mappings=LayerMapping()) -> Callable[['Frame'], FrameBackend]:
        """Dissect frame from data"""
        return lambda f: DissectorBackend(f, mappings, data)

    @classmethod
    def dissect_file(cls, file: pathlib.Path) -> Callable[['Frame'], FrameBackend]:
        """Dissect frame from file"""
        data = Raw.file(file)
        return lambda f: DissectorBackend(f, LayerMapping(), data)

    @classmethod
    def dissect_pull(cls, frame_type: Type[F], queue: RawDataQueue, mappings=LayerMapping()) -> Optional[F]:
        """Dissect frame from queue, if enough data. Pulls the frame data if success."""
        if not queue.head:
            return None  # no data
        try:
            f = frame_type(cls.dissect(queue.head.fixed, mappings=mappings))
            length = f.byte_length()
            queue.pull(byte_length=length)
            return f
        except EOFError:
            return None

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
    def dump(cls, frame: Frame, bit_offset=80, indent='', width=0, copy_sub_frames=False) -> str:
        """Dump frame to string"""
        be = cast(BackendImplementation, frame.backend)
        if copy_sub_frames:
            be = be.copy()
        return be.dump(bit_offset, indent, width, copy_sub_frames=copy_sub_frames)

