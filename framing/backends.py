from typing import Dict, Any

from typing_extensions import Self

from framing.base import FrameBackend, FieldBase, S, T, Structure, EncodingState
from framing.raw_data import RawData, Raw


class EditableBackend(FrameBackend):
    def __init__(self):
        super().__init__()
        self.changes: Dict[FieldBase, Any] = {}

    def get(self, field: FieldBase[S, T], frame: 'Frame[S]') -> T:
        return self.changes.get(field, field.default_value)

    def set(self, field: FieldBase[S, T], frame: 'Frame[S]', value: T) -> Self:
        self.changes[field] = value

    def __repr__(self):
        r = []
        state = EncodingState()
        for f in self.structure.fields.values():
            v = self.get(f, self.frame)
            raw = f.encode(v, state)
            r.append(f"{f.field_name} = {raw}")
        return "\n".join(r)

    def encode(self) -> RawData:
        self.structure.commit(self.frame)
        f_list = []
        state = EncodingState()
        for f in self.structure.fields.values():
            v = self.get(f, self.frame)
            f_list.append(f.encode(v, state))
        return Raw.merge(f_list)
