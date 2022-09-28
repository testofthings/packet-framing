import copy
from typing import Dict, Any, cast

from typing_extensions import Self

from framing.base import Frame, FrameBackend, FieldBase, F, T, EncodingState
from framing.raw_data import RawData, Raw


class ComposingBackend(FrameBackend):
    """Backend to compose a frame"""
    def __init__(self, frame: Frame):
        super().__init__(frame)
        self.changes: Dict[FieldBase, Any] = {}

    def get(self, field: FieldBase[F, T]) -> T:
        return self.changes.get(field, field.default_value)

    def set(self, field: FieldBase[F, T], value: T) -> Self:
        self.changes[field] = value
        return self

    def copy(self) -> Self:
        n_frame = copy.copy(self.frame)
        c = ComposingBackend(n_frame)
        n_frame.backend = c
        c.changes.update(self.changes)
        return c

    def __repr__(self):
        # create a copy to show, so that we do not update state
        c = self.copy()
        c.encode()
        return c.pretty_print()

    def encode(self) -> RawData:
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
    def __init__(self, frame: Frame, data: RawData):
        super().__init__(frame)
        self.is_decoding = True
        self.data = data
        self.length_cache: Dict[FieldBase, int] = {}
        self.cache: Dict[FieldBase, Any] = {}

    def get(self, field: FieldBase[F, T]) -> T:
        v = self.cache.get(field)
        if v is None:
            bit_offset = self._field_offset(field)
            data = self.data.tailBits(bit_offset)
            if field.decode_length_procedure:
                f_len = field.decode_length_procedure(self.frame)
                data = data.subBlockBits(0, f_len)
            v = field.decode(data, self)
            self.cache[field] = v
        return v

    def _field_offset(self, field: FieldBase) -> int:
        off = field.offset.fixed_bit_offset
        prefix = field.offset.prefix
        if prefix:
            # resolve prefix dynamic length
            off += prefix.get_offset(self)
            if prefix.variable_field:
                if prefix.variable_field.decode_length_procedure:
                    f_len = prefix.variable_field.decode_length_procedure(self.frame)
                    off += f_len
                else:
                    off += prefix.variable_field.get_bit_length(self.frame)
        return off

    def set(self, field: FieldBase[F, T], value: T) -> Self:
        raise NotImplementedError("set() not supported")

    def encode(self) -> RawData:
        bit_length = self.frame.get_bit_length()
        return self.data.tailBits(bit_length)

    def input_data(self) -> RawData:
        return self.data
