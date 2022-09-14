import copy
from typing import Dict, Any, cast

from typing_extensions import Self

from framing.base import Frame, FrameBackend, FieldBase, F, T, EncodingState
from framing.raw_data import RawStream, Raw


class ComposingBackend(FrameBackend):
    """Backend to compose a frame"""
    def __init__(self, frame_type: Any, frame: Frame):
        super().__init__(frame_type, frame)
        self.changes: Dict[FieldBase, Any] = {}

    def get(self, field: FieldBase[F, T]) -> T:
        return self.changes.get(field, field.default_value)

    def set(self, field: FieldBase[F, T], value: T) -> Self:
        self.changes[field] = value
        return self

    def copy(self) -> Self:
        n_frame = copy.copy(self.frame)
        c = ComposingBackend(self.frame_type, n_frame)
        n_frame.backend = c
        c.changes.update(self.changes)
        return c

    def __repr__(self):
        # create a copy to show, so that we do not update state
        c = self.copy()
        c.encode()
        return c.pretty_print()

    def encode(self) -> RawStream:
        self.structure.commit(self.frame)
        f_list = []
        state = EncodingState()
        for f in self.structure.fields.values():
            v = self.get(f)
            f_list.append(f.encode(v, state))
        return Raw.merge(f_list)

    def pretty_print(self, indent='') -> str:
        r = []
        name_space = max([len(n) for n in self.structure.fields.keys()]) + 1
        state = EncodingState()
        bit_off = 0
        for n, f in self.structure.fields.items():
            v = self.get(f)
            ev = f.encode(v, state)
            sv = ev.dump(always_wide=True).split("\n")
            i_off = bit_off
            for i in range(0, len(sv)):
                line = f"{i_off // 8:06x} {indent}"
                if i == 0:
                    line += n + " " * (name_space - len(n))
                else:
                    line += " " * name_space
                line += sv[i]
                r.append(line)
                i_off += 16 * 8
            bit_off += f.get_bit_length(self.frame)
        return "\n".join(r)


class DissectorBackend(FrameBackend):
    """Backend to dissect frame from raw data"""
    def __init__(self, frame_type: Any, frame: Frame, data: RawStream):
        super().__init__(frame_type, frame)
        self.data = data
        self.cache: Dict[FieldBase, Any] = {}

    def get(self, field: FieldBase[F, T]) -> T:
        v = self.cache.get(field)
        if v is None:
            bit_offset = field.offset.get_offset(self)
            v = field.decode(self.data.tailBits(bit_offset), self)
            self.cache[field] = v
        return v

    def set(self, field: FieldBase[F, T], value: T) -> Self:
        raise NotImplementedError("set() not supported")

    def encode(self) -> RawStream:
        bit_length = self.structure.fields_length.get_offset(self)
        return self.data.subBlockBits(0, bit_length)
