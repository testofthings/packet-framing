from typing import Dict, Any

from typing_extensions import Self

from framing.base import FrameBackend, FieldBase, S, T, Structure


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
        for f in struct.fields.values():
            v = self.get(f, self.frame)
            r.append(f"{f.field_name} = {v}")
        return "\n".join(r)


