import copy
from typing import Dict, Any, cast

from typing_extensions import Self

from framing.base import Frame, FrameBackend, FieldBase, S, T, EncodingState
from framing.raw_data import RawData, Raw


class EditableBackend(FrameBackend):
    def __init__(self, frame: Frame):
        super().__init__(frame)
        self.changes: Dict[FieldBase, Any] = {}

    def get(self, field: FieldBase[S, T], frame: Frame[S]) -> T:
        return self.changes.get(field, field.default_value)

    def set(self, field: FieldBase[S, T], frame: Frame[S], value: T) -> Self:
        self.changes[field] = value
        return self

    def copy(self) -> Self:
        n_frame = copy.copy(self.frame)
        c = EditableBackend(n_frame)
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
            v = self.get(f, self.frame)
            f_list.append(f.encode(v, state))
        return Raw.merge(f_list)

    def pretty_print(self, indent='') -> str:
        r = []
        name_space = max([len(n) for n in self.structure.fields.keys()]) + 1
        state = EncodingState()
        bit_off = 0
        for n, f in self.structure.fields.items():
            v = self.get(f, self.frame)
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
