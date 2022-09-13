import inspect
import typing
from typing import Optional, Callable, List, Any

from typing_extensions import Self

from framing.codecs import IntegerCodec, FixedLittleEndianCodec
from framing.raw_data import RawData, Raw

# Frame or subclass
S = typing.TypeVar("S", bound='Frame')

# Field value type
T = typing.TypeVar("T")


class EncodingState:
    """Encoding state"""
    pass


class FieldOffset:
    def __init__(self, field: Optional['FieldBase'] = None):
        self.prefix: Optional['FieldOffset'] = None
        self.fixed_bit_offset = 0
        self.variable_field: Optional[FieldBase] = field

    def get_offset(self, backend: 'FrameBackend') -> int:
        off = self.prefix.get_offset(backend) if self.prefix else 0
        off += self.fixed_bit_offset
        if self.variable_field:
            off += self.variable_field.get_bit_length(backend.frame)
        return off

    def __repr__(self):
        r = []
        if self.prefix:
            r.append(f"{self.prefix}")
        r.append(f"{self.fixed_bit_offset}")
        if self.variable_field:
            r.append(f"{self.variable_field}")
        return " + ".join(r)


class FieldBase(typing.Generic[S, T]):
    """Base class for fields"""
    def __init__(self, name: str, type_name: str, default_value: T):
        self.field_name = name
        self.type_name = type_name
        self.default_value = default_value
        self.fixed_bit_length = -1
        self.offset = FieldOffset(self)
        self.commit_procedure: Optional[Callable[[S], T]] = None

    def get(self, frame: S) -> T:
        return frame.get(self)

    def set(self, frame: S, value: T) -> T:
        frame.set(self, value)
        return value

    def get_bit_length(self, frame: S) -> int:
        raise NotImplementedError()

    def get_byte_length(self, frame: S) -> int:
        return self.get_bit_length(frame) // 8

    def encode(self, value: T, state: EncodingState) -> RawData:
        raise NotImplementedError()

    def to_string(self, frame: S) -> str:
        """A string representation of current value, for unit tests"""
        enc = self.encode(self.get(frame), EncodingState())
        return f"{enc}"

    def at_commit(self, procedure: Callable[[S], T]) -> Self:
        self.commit_procedure = procedure
        return self

    def __repr__(self):
        return f"{self.field_name}: {self.type_name}"


class FrameBackend:
    """Base class for frame backend"""
    def __init__(self, frame: 'Frame'):
        self.frame = frame
        self.structure = Structure.get_struct(frame)
        if not self.structure.built:
            self.structure.finish_building(frame)

    def get(self, field: FieldBase[S, T], frame: 'Frame') -> T:
        raise NotImplementedError()

    def set(self, field: FieldBase[S, T], frame: 'Frame', value: T) -> Self:
        raise NotImplementedError("Editing not allowed with this backend")

    def encode(self) -> RawData:
        """Encode the frame into bytes"""
        raise NotImplementedError()


class Frame(typing.Generic[S]):
    """Base class for frames"""
    def __init__(self, backend: FrameBackend):
        self.backend = backend

    def get(self, field: FieldBase[S, T]) -> T:
        return self.backend.get(field, self)

    def set(self, field: FieldBase[S, T], value: T) -> Self:
        self.backend.set(field, self, value)
        return self

    def __repr__(self):
        return self.backend.__repr__()


class RawField(FieldBase[S, RawData]):
    """Raw data field"""
    def __init__(self, name: str, default_value: RawData):
        super().__init__(name, "raw", default_value)
        self.offset.resolver = lambda f: self.get_bit_length(f)  # set to null, if fixed length

    def fixed_length(self, bit_length: int):
        self.fixed_bit_length = bit_length

    def get(self, frame: S) -> RawData:
        return frame.get(self)

    def set(self, frame: S, value: RawData) -> RawData:
        frame.set(self, value)
        return value

    def get_bit_length(self, frame: S) -> int:
        return self.get(frame).bit_length()

    def get_byte_length(self, frame: S) -> int:
        return self.get(frame).byte_length()

    def encode(self, value: RawData, state: EncodingState) -> RawData:
        return value


class IntField(FieldBase[S, int]):
    """Integer field"""
    def __init__(self, name: str, codec: IntegerCodec, default_value: int):
        super().__init__(name, "int", default_value)
        self.codec = codec
        self.fixed_bit_length = codec.get_fixed_bit_length()

    def get_bit_length(self, frame: S) -> int:
        if self.fixed_bit_length >= 0:
            return self.fixed_bit_length
        return self.codec.get_bit_length(self.get(frame))

    def get_byte_length(self, frame: S) -> int:
        if self.fixed_bit_length >= 0:
            return self.fixed_bit_length // 8
        return self.codec.get_bit_length(self.get(frame)) // 8

    def encode(self, value: int, state: EncodingState) -> RawData:
        return self.codec.encode(value)


class StringField(FieldBase[S, str]):
    """String field"""
    def __init__(self, name: str, default_value: str):
        super().__init__(name, "str", default_value)

    def encode(self, value: str, state: EncodingState) -> RawData:
        return Raw.empty  # FIXME


# Type for sub-frames
F = typing.TypeVar("F", bound=Frame)


class Subframe(FieldBase[S, F]):
    """Subframe field"""
    def __init__(self, name: str, struct_type: typing.Type[F]):
        super().__init__(name, f"{struct_type}", struct_type())
        self.struct_type = struct_type

    def new(self, backend: FrameBackend) -> F:
        return self.struct_type(backend)

    def get(self, frame: S) -> F:
        return self.new(frame.backend)


class Structure(typing.Generic[S]):
    """Structure definition for a frame"""
    def __init__(self):
        self.fields: typing.Dict[str, FieldBase[S]] = {}
        self.fields_length = FieldOffset()
        self.commit_procedures: List[Callable[[S], None]] = []
        self.built = False

    def commit(self, frame: S):
        for cp in self.commit_procedures:
            cp(frame)

    def raw(self, bits: int = None, bytes: int = None, default: RawData = Raw.empty,
            name: str = None) -> RawField[S]:
        fn = self._get_a_name(name)
        default = default if default else Raw.zeroes(bit_length=bits, byte_length=bytes)
        f: RawField[S] = RawField(fn, default)
        if bits is not None:
            f.fixed_length(bits)
        if bytes is not None:
            f.fixed_length(bytes * 8)
        self.fields[fn] = f
        return f

    def integer(self, bits: int = None, bytes: int = None, default=0, name: str = None) -> FieldBase[S, int]:
        fn = self._get_a_name(name)
        if bytes is not None:
            f: FieldBase[S, int] = IntField(fn, FixedLittleEndianCodec(bytes), default)
        else:
            raise Exception("Only supporting full-byte integers now")
        self.fields[fn] = f
        return f

    def string(self, name: str = None, default="") -> FieldBase[S, str]:
        fn = self._get_a_name(name)
        f: FieldBase[S, str] = StringField(fn, default)
        self.fields[fn] = f
        return f

    def struct(self, struct_type: typing.Type[F], name: str = None) -> FieldBase[S, F]:
        fn = self._get_a_name(name)
        f: FieldBase[S, F] = Subframe(fn, struct_type)
        self.fields[fn] = f
        return f

    def at_commit(self, update: Callable[[S], None]):
        self.commit_procedures.append(update)

    @classmethod
    def get_struct(cls, frame: Frame[S]) -> 'Structure[S]':
        if hasattr(frame, "fields_"):
            return getattr(frame, "fields_")  # underscored to avoid naming collision
        return getattr(frame, "fields")

    def _get_a_name(self, override: Optional[str]) -> str:
        """Get name or temporary name for a field"""
        return override if override else f"__{len(self.fields)}"

    def finish_building(self, frame: S):
        # find field names
        i_names: typing.Dict[FieldBase, str] = {}
        for member in inspect.getmembers(frame):
            name, v = member
            if isinstance(v, FieldBase):
                i_names[v] = name
        # ...keep order of fields
        old_names = self.fields.copy()
        self.fields.clear()
        for n, v in old_names.items():
            nn = i_names[v] if n.startswith("__") else n
            v.field_name = nn
            self.fields[nn] = v
        self.built = True

        # resolve offsets
        prefix = None
        prefix_offset = 0
        for f in self.fields.values():
            f.offset.prefix = prefix
            f.offset.fixed_bit_offset += prefix_offset
            if f.fixed_bit_length < 0:
                # field length calculated dynamically
                prefix = f.offset
                prefix_offset = 0
            else:
                # fixed length, just add to offset
                f.offset.variable_field = None  # not variable
                prefix_offset += f.fixed_bit_length
        self.fields_length.prefix = prefix
        self.fields_length.fixed_bit_offset = prefix_offset

        # collect commit procedures from fields
        for f in self.fields.values():
            if f.commit_procedure is not None:
                def procedure(fr: S):
                    value = f.commit_procedure(fr)
                    fr.set(f, value)
                self.commit_procedures.append(procedure)

    def __repr__(self) -> str:
        r = []
        for f in self.fields.values():
            r.append(f"{f.field_name}: {f.type_name}")
        return "\n".join(r)
