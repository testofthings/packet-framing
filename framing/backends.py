from typing import Dict, Any

from typing_extensions import Self

from framing.base import FrameBackend, FieldBase, S, T, Structure, EncodingState
from framing.raw_data import RawData


class EditableBackend(FrameBackend):
    def __init__(self):
        super().__init__()
        self.changes: Dict[FieldBase, Any] = {}

    def get(self, field: FieldBase[S, T], frame: 'Frame[S]') -> T:
        return self.changes.get(field, field.default_value)

    def set(self, field: FieldBase[S, T], frame: 'Frame[S]', value: T) -> Self:
        self.changes[field] = value

    def __repr__(self):
        struct = Structure.get_struct(self.frame)
        r = []
        state = EncodingState()
        for f in struct.fields.values():
            v = self.get(f, self.frame)
            raw = f.encode(v, state)
            r.append(f"{f.field_name} = {raw}")
        return "\n".join(r)


