import inspect
from typing import Optional, Callable, List, Tuple
import typing

from typing_extensions import Self

from framing.codecs import IntegerCodec, FixedLittleEndianCodec
from framing.raw_data import Raw, RawData

# Frame type
F = typing.TypeVar("F", bound='Frame')

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
        off = self.fixed_bit_offset
        prefix = self.prefix
        if prefix:
            # resolve prefix dynamic length
            off += prefix.get_offset(backend)
            if prefix.variable_field:
                off += prefix.variable_field.get_bit_length(backend.frame)
        return off

    def __repr__(self):
        r = []
        if self.prefix:
            r.append(f"{self.prefix}")
        r.append(f"{self.fixed_bit_offset}")
        if self.variable_field:
            r.append(f"{self.variable_field}")
        return " + ".join(r)


class FieldBase(typing.Generic[F, T]):
    """Base class for fields"""
    def __init__(self, type_name: str, default_value: T):
        self.field_name = "field?"
        self.type_name = type_name
        self.default_value = default_value
        self.fixed_bit_length = -1
        self.offset = FieldOffset(self)
        self.commit_procedure: Optional[Callable[[F], T]] = None
        self.decode_length_procedure: Optional[Callable[[F], int]] = None

    def get(self, frame: F) -> T:
        return frame.backend.get(self)

    def __getitem__(self, frame: F) -> T:
        return frame.backend.get(self)

    def set(self, frame: F, value: T) -> F:
        frame.backend.set(self, value)
        return frame

    def __setitem__(self, frame: F, value: T) -> F:
        frame.backend.set(self, value)
        return frame

    def get_bit_length(self, frame: F) -> int:
        raise NotImplementedError()

    def get_byte_length(self, frame: F) -> int:
        return self.get_bit_length(frame) // 8

    def encode(self, value: T, state: EncodingState) -> RawData:
        raise NotImplementedError()

    def decode(self, data: RawData, backend: 'FrameBackend') -> T:
        raise NotImplementedError()

    def to_string(self, frame: F) -> str:
        """A string representation of current value, for unit tests"""
        enc = self.encode(self.get(frame), EncodingState())
        return f"{enc}"

    def at_commit(self, procedure: Callable[[F], T]) -> Self:
        self.commit_procedure = procedure
        return self

    def decode_length(self, procedure: Callable[[F], int]) -> Self:
        self.decode_length_procedure = procedure
        return self

    def __repr__(self):
        return f"{self.field_name}: {self.type_name}"


class FrameBackend:
    """Base class for frame backend"""
    def __init__(self, frame: 'Frame'):
        self.frame = frame
        self.structure = Structure.get_struct(frame)
        self.is_decoding = False
        if not self.structure.built:
            self.structure.finish_building(frame)

    def get(self, field: FieldBase[F, T]) -> T:
        raise NotImplementedError()

    def set(self, field: FieldBase[F, T], value: T) -> Self:
        raise NotImplementedError("Editing not allowed with this backend")

    def encode(self) -> RawData:
        """Encode the frame into bytes"""
        raise NotImplementedError()

    def input_data(self) -> RawData:
        """Get input data when decoding, empty otherwise"""
        return Raw.empty


class Frame:
    """Base class for frames"""
    def __init__(self, backend_factory: Callable[['Frame'], FrameBackend]):
        self.backend = backend_factory(self)

    def get_bit_length(self) -> int:
        """Get frame bit length"""
        st = self.backend.structure
        return st.fields_length.get_offset(self.backend)

    def get_byte_length(self) -> int:
        """Get frame byte length"""
        st = self.backend.structure
        return st.fields_length.get_offset(self.backend) // 8

    def encode(self) -> RawData:
        return self.backend.encode()

    def __repr__(self):
        return self.backend.__repr__()


class RawField(FieldBase[F, RawData]):
    """Raw data field"""
    def __init__(self, default_value: RawData):
        super().__init__("raw", default_value)

    def fixed_length(self, bit_length: int):
        self.fixed_bit_length = bit_length

    def get_bit_length(self, frame: F) -> int:
        if self.fixed_bit_length >= 0:
            return self.fixed_bit_length

        # do not know my length without encoding/decoding it
        v: RawData = frame.backend.get(self)
        return v.bit_length()

    def get_byte_length(self, frame: F) -> int:
        return self.get_bit_length(frame) // 8

    def encode(self, value: RawData, state: EncodingState) -> RawData:
        return value

    def decode(self, data: RawData, backend: 'FrameBackend') -> RawData:
        if self.fixed_bit_length < 0:
            return data  # read it all
        return data.subBlockBits(0, self.fixed_bit_length)


class IntField(FieldBase[F, int]):
    """Integer field"""
    def __init__(self, codec: IntegerCodec, default_value: int):
        super().__init__("int", default_value)
        self.codec = codec
        self.fixed_bit_length = codec.get_fixed_bit_length()

    def get_bit_length(self, frame: F) -> int:
        if self.fixed_bit_length >= 0:
            return self.fixed_bit_length
        return self.codec.get_bit_length(self.get(frame))

    def get_byte_length(self, frame: F) -> int:
        if self.fixed_bit_length >= 0:
            return self.fixed_bit_length // 8
        return self.codec.get_bit_length(self.get(frame)) // 8

    def encode(self, value: int, state: EncodingState) -> RawData:
        return self.codec.encode(value)

    def decode(self, data: RawData, backend: 'FrameBackend') -> T:
        return self.codec.decode(data)


class StringField(FieldBase[F, str]):
    """String field"""
    def __init__(self, default_value: str):
        super().__init__("str", default_value)

    def encode(self, value: str, state: EncodingState) -> RawData:
        return Raw.empty  # FIXME


class Structure(typing.Generic[F]):
    """Structure definition for a frame"""
    def __init__(self):
        self.fields: typing.Dict[str, FieldBase] = {}
        self.fields_length = FieldOffset()
        self.commit_procedures: List[Callable[[F], None]] = []
        self.built = False

    def commit(self, frame: F):
        for cp in self.commit_procedures:
            cp(frame)

    def raw(self, bits: int = None, bytes: int = None, default: RawData = Raw.empty,
            name: str = None) -> RawField[F]:
        fn = self._get_a_name(name)
        default = default if default else Raw.zeroes(bit_length=bits, byte_length=bytes)
        f: RawField[F] = RawField(default)
        if bits is not None:
            f.fixed_length(bits)
        if bytes is not None:
            f.fixed_length(bytes * 8)
        self.fields[fn] = f
        return f

    def integer(self, bits: int = None, bytes: int = None, default=0, name: str = None) -> IntField[F]:
        fn = self._get_a_name(name)
        if bytes is not None:
            f = IntField(FixedLittleEndianCodec(bytes), default)
        else:
            raise Exception("Only supporting full-byte integers now")
        self.fields[fn] = f
        return f

    def string(self, name: str = None, default="") -> StringField[F]:
        fn = self._get_a_name(name)
        f = StringField(default)
        self.fields[fn] = f
        return f

    def at_commit(self, update: Callable[[F], None]):
        self.commit_procedures.append(update)

    @classmethod
    def get_struct(cls, frame_type: F) -> 'Structure[F]':
        if hasattr(frame_type, "structure_"):
            return getattr(frame_type, "structure_")  # underscored to avoid naming collision
        return getattr(frame_type, "structure")

    def _get_a_name(self, override: Optional[str]) -> str:
        """Get name or temporary name for a field"""
        return override if override else f"__{len(self.fields)}"

    def finish_building(self, frame: F):
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
            self.fields[nn] = v
            v.field_name = nn
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
        def make_procedure(field: FieldBase):
            def procedure(fr: F):
                value = field.commit_procedure(fr)
                field.set(fr, value)
            return procedure
        for f in self.fields.values():
            if f.commit_procedure is not None:
                self.commit_procedures.append(make_procedure(f))

    def __repr__(self) -> str:
        r = []
        for n, f in self.fields.items():
            r.append(f"{n}: {f}")
        return "\n".join(r)
