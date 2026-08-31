"""Frame utilities for processing and composing frames"""

import pathlib
from typing import Callable, cast, Type, Dict, Any, Optional

from framing.backends import ComposingBackend, DissectorBackend, BackendImplementation
from framing.base import Frame, FrameBackend, LayerMapping, F, T
from framing.data_queue import RawDataQueue
from framing.raw_data import RawData, Raw

class Frames:
    """Frame processing utilities"""
    @classmethod
    def compose(cls, int_swap: bool = False) -> Callable[['Frame'], FrameBackend]:
        """Create new frame for composing. The integer octet order can be reversed from the declared one."""
        return lambda f: ComposingBackend(f, LayerMapping(), int_swap)

    @classmethod
    def dissect(cls, data: RawData, mappings: LayerMapping | None = None,
                int_swap: bool = False) -> Callable[['Frame'], FrameBackend]:
        """Dissect frame from data. The integer octet order can be reversed from the declared one."""
        if mappings is None:
            mappings = LayerMapping()
        return lambda f: DissectorBackend(f, mappings, data, int_swap)

    @classmethod
    def dissect_file(cls, file: pathlib.Path, int_swap: bool = False) -> Callable[['Frame'], FrameBackend]:
        """Dissect frame from file. The integer octet order can be reversed from the declared one."""
        data = Raw.file(file)
        return lambda f: DissectorBackend(f, LayerMapping(), data, int_swap)

    @classmethod
    def check_file(cls, frame: F, check: Callable[[F], Any], mappings: LayerMapping | None = None) -> F:
        """Check a frame dissected from a file, close the file if the check fails, add the mappings"""
        try:
            check(frame)
        except ValueError:
            cls.close(frame)  # do not leave the file open
            raise
        return mappings.add_to(frame) if mappings else frame

    @classmethod
    def dissect_pull(cls, frame_type: Type[F], queue: RawDataQueue,
                     mappings: LayerMapping | None = None) -> Optional[F]:
        """Dissect frame from queue, if enough data. Pulls the frame data if success."""
        if not queue.head:
            return None  # no data
        if mappings is None:
            mappings = LayerMapping()
        try:
            f = frame_type(cls.dissect(queue.head.fixed, mappings=mappings))
            length = f.byte_length()
            queue.pull(byte_length=length)
            return f
        except EOFError:
            return None

    @classmethod
    def process(cls, frame: F, procedures: Dict[Type[Frame], Callable[[Any], T]]) -> Optional[T]:
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
    def dump(cls, frame: Frame, bit_offset: int = 80, indent: str = '', width: int = 0,
             copy_sub_frames: bool =False) -> str:
        """Dump frame to string"""
        be = cast(BackendImplementation, frame.backend)
        if copy_sub_frames:
            be = be.copy()
        return be.dump(bit_offset, indent, width, copy_to_avoid_update=copy_sub_frames)
