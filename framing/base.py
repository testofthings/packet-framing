import traceback
import typing
from typing import Optional, Tuple
from typing_extensions import Self

from framing.raw_data import RawData

# Frame or subclass
S = typing.TypeVar("S", bound='Frame')

# Field value type
T = typing.TypeVar("T")


class FieldBase(typing.Generic[S, T]):
    """Base class for fields"""
    def __init__(self, name: str, type_name: str):
        self.field_name = name
        self.type_name = type_name

    def get(self, frame: 'Frame[S]') -> T:
        raise NotImplementedError()

    def set(self, frame: 'Frame[S]', value: T) -> T:
        pass


class FrameBackend:
    """Base class for frame backend"""
    def get(self, field: FieldBase[S, T], frame: 'Frame[S]') -> T:
        return field.get(frame)

    def set(self, field: FieldBase[S, T], frame: 'Frame[S]', value: T) -> Self:
        raise Exception("Editing not allowed with this backend")


class Frame(typing.Generic[S]):
    """Base class for frames"""
    def __init__(self, backend=FrameBackend()):
        self.backend = backend

    def get(self, field: FieldBase[S, T]) -> T:
        return self.backend.get(field, self)

    def set(self, field: FieldBase[S, T], value: T) -> Self:
        self.backend.set(field, self, value)
        return self

    def __repr__(self):
        struct = getattr(self, "struct_")
        return struct.__repr__()


class RawField(FieldBase[S, RawData]):
    """Raw data field"""
    def __init__(self, name: str):
        super().__init__(name, "int")

    def get(self, frame: 'Frame[S]') -> RawData:
        return RawData()


class IntField(FieldBase[S, int]):
    """Integer field"""
    def __init__(self, name: str):
        super().__init__(name, "int")

    def get(self, frame: 'Frame[S]') -> T:
        return 0


class StringField(FieldBase[S, str]):
    """String field"""
    def __init__(self, name: str):
        super().__init__(name, "str")

    def get(self, frame: 'Frame[S]') -> T:
        return ""


# Type for sub-frames
F = typing.TypeVar("F", bound=Frame)


class Subframe(FieldBase[S, F]):
    """Subframe field"""
    def __init__(self, name: str, struct_type: typing.Type[F]):
        super().__init__(name, f"{struct_type}")
        self.struct_type = struct_type

    def new(self, backend: FrameBackend) -> F:
        return self.struct_type(backend)

    def get(self, frame: 'Frame[S]') -> F:
        return self.new(frame.backend)


class Structure(typing.Generic[S]):
    """Structure definition for a frame"""
    def __init__(self):
        self.fields: typing.Dict[str, FieldBase[S]] = {}

    def raw_field(self, bits: int = None, bytes: int = None, name: str = None) -> FieldBase[S, RawData]:
        fn, cn = self._get_field_name(name)
        f = RawField(fn)
        self.fields[fn] = f
        return f

    def int_field(self, bits: int = None, bytes: int = None, name: str = None) -> FieldBase[S, int]:
        fn, cn = self._get_field_name(name)
        f = IntField(fn)
        self.fields[fn] = f
        return f

    def string_field(self, name: str = None) -> FieldBase[S, str]:
        fn, cn = self._get_field_name(name)
        f = StringField(fn)
        self.fields[fn] = f
        return f

    def struct_field(self, struct_type: typing.Type[F], name: str = None) -> FieldBase[S, F]:
        fn, cn = self._get_field_name(name)
        f = Subframe(fn, struct_type)
        self.fields[fn] = f
        return f

    @classmethod
    def _get_field_name(self, override: Optional[str]) -> Tuple[str, str]:
        stack = traceback.extract_stack(limit=3)
        f_name = override or stack[-2].name
        cl_name = stack[-3].name
        return f_name, cl_name

    def __repr__(self) -> str:
        r = []
        for f in self.fields.values():
            r.append(f"{f.field_name}: {f.type_name}")
        return "\n".join(r)
