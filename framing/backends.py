from typing_extensions import Self

from framing.base import FrameBackend, FieldBase, S, T


class EditableBackend(FrameBackend):
    def get(self, field: FieldBase[S, T], frame: 'Frame[S]') -> T:
        return field.get(frame)

    def set(self, field: FieldBase[S, T], frame: 'Frame[S]', value: T) -> Self:
        raise Exception("Editing not allowed with this backend")
