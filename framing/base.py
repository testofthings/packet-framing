import inspect
import typing
from typing import Optional, Callable, List, Type, Any, Dict

from typing_extensions import Self

from framing.codecs import IntegerCodec, IntegerFormat, ValueCodec
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
        self.min_tail_length = 0

    def __repr__(self):
        r = []
        if self.prefix:
            r.append(f"{self.prefix}")
        r.append(f"{self.fixed_bit_offset}")
        if self.variable_field:
            r.append(f"{self.variable_field}")
        return " + ".join(r)


class Calculator:
    """Integer value calculator"""
    def __init__(self, next_step: Optional['Calculator']):
        self.next_step = next_step

    def pull(self, backend: 'FrameBackend') -> float:
        """Pull value from source"""
        return self.next_step.pull(backend)

    def push(self, backend: 'FrameBackend', value: float):
        """Push value to source"""
        self.next_step.push(backend, value)


class FieldPointer(typing.Generic[F, T]):
    """Path pointing to a field"""
    def get(self, frame: F) -> T:
        raise NotImplementedError()


class FieldBase(FieldPointer[F, T]):
    """Base class for fields"""
    def __init__(self, type_name: str, default_value: T):
        self.field_name = "field?"
        self.type_name = type_name
        self.default_value = default_value
        self.fixed_bit_length = -1
        self.offset = FieldOffset(self)
        self.structure: Optional['Sturcture'] = None  # set by structure herself
        self.length_resolver: Optional[Calculator] = None
        self.consumed_by: Optional[FieldBase[F, Any]] = None

    def get(self, frame: F) -> T:
        return frame.backend.get(self)

    def get_default_value(self, frame: F) -> T:
        return self.default_value

    def __getitem__(self, frame: F) -> T:
        return frame.backend.get(self)

    def set(self, frame: F, value: T) -> F:
        frame.backend.set(self, value)
        return frame

    def __setitem__(self, frame: F, value: T) -> F:
        frame.backend.set(self, value)
        return frame

    def get_bit_length(self, frame: F, value: Optional[T] = None) -> int:
        raise NotImplementedError()

    def get_byte_length(self, frame: F, value: Optional[T] = None) -> int:
        return self.get_bit_length(frame, value) // 8

    def as_frame(self, frame: F) -> 'Frame':
        """Return value as frame, use type information when available"""
        return frame.backend.get_as_frame(self)

    def encode(self, value: T, state: EncodingState) -> RawData:
        raise NotImplementedError()

    def decode(self, data: RawData, backend: 'FrameBackend') -> T:
        raise NotImplementedError()

    def to_string(self, frame: F) -> str:
        """A string representation of current value, for unit tests"""
        enc = self.encode(self.get(frame), EncodingState())
        return f"{enc}"

    def __truediv__(self, other: 'FieldBase[Any, T]') -> 'FieldPath':
        return FieldPath(self) / other

    def __repr__(self):
        return f"{self.field_name}: {self.type_name}"


class FrameBackend:
    """Base class for frame backend"""
    def __init__(self, frame: 'Frame'):
        self.frame = frame
        self.structure = FrameStructure.get_struct(frame)
        self.is_decoding = False
        if not self.structure.built:
            self.structure.finish_building(frame)
        self.parent: Optional[FrameBackend] = None

    def get(self, field: FieldBase[F, T]) -> T:
        raise NotImplementedError()

    def set(self, field: FieldBase[F, T], value: T) -> Self:
        raise NotImplementedError("Editing not allowed with this backend")

    def get_bit_offset(self, offset: FieldOffset) -> int:
        raise NotImplementedError()

    def resolve_bit_length(self, field: FieldBase[F, T]) -> int:
        """Resolve bit length without encoding, return -1 if not available"""
        return -1

    def get_item(self, sequence_field: FieldBase, item_field: FieldBase[F, T], index: int):
        raise NotImplementedError()

    def iterate(self, sequence_field: FieldBase, item_field: FieldBase[F, T]) -> typing.Iterator[T]:
        """Iterate sequence field values without storing them"""
        raise NotImplementedError()

    def get_as_frame(self, field: FieldBase[F, T]) -> 'Frame':
        """Get field value as frame, use type information when available"""
        raise NotImplementedError()

    def factory(self, decode: RawData = None) -> Callable[['Frame'], 'FrameBackend']:
        """Create a fresh backend for given frame"""
        raise NotImplementedError()

    def get_bit_length(self) -> int:
        """Get frame bit length"""
        raise NotImplementedError()

    def encode(self) -> RawData:
        """Encode the frame into bytes"""
        raise NotImplementedError()

    def input_data(self) -> RawData:
        """Get input data when decoding, empty otherwise"""
        return Raw.empty

    def add_mapping(self, mapping: 'LayerMapping') -> Self:
        """All layer mappings"""
        return self

    def dump(self, bit_offset=0, indent='', width=0, copy_to_avoid_update=False) -> str:
        raise NotImplementedError()


class Frame:
    """Base class for frames"""
    def __init__(self, backend_factory: Callable[['Frame'], FrameBackend]):
        self.backend = backend_factory(self)

    def get_bit_length(self) -> int:
        """Get frame bit length"""
        return self.backend.get_bit_length()

    def get_byte_length(self) -> int:
        """Get frame byte length"""
        return self.backend.get_bit_length() // 8

    def encode(self) -> RawData:
        """Encode the frame into bytes"""
        return self.backend.encode()

    def __repr__(self):
        return self.backend.__repr__()


class FrameStructure(typing.Generic[F]):
    """Frame structure definition"""
    def __init__(self):
        self.structure_name = "Unnamed"
        self.fields: typing.Dict[str, FieldBase] = {}
        self.fields_length = FieldOffset()
        self.commit_procedures: List[typing.Tuple[Optional[FieldBase], Callable[[F], None]]] = []
        self.built = False

    def commit(self, frame: F):
        for cp in self.commit_procedures:
            cp[1](frame)

    @classmethod
    def get_struct(cls, frame_type: F) -> 'FrameStructure[F]':
        if hasattr(frame_type, "structure_"):
            return getattr(frame_type, "structure_")  # underscored to avoid naming collision
        return getattr(frame_type, "structure")

    def is_field_here(self, field: FieldBase) -> bool:
        f = self.fields.get(field.field_name)
        return f == field

    def _get_a_name(self, override: Optional[str]) -> str:
        """Get name or temporary name for a field"""
        return override if override else f"__{len(self.fields)}"

    def finish_building(self, frame: F):
        # find field names
        self.structure_name = type(frame).__name__
        i_names: typing.Dict[FieldBase, str] = {}
        for member in inspect.getmembers(frame):
            name, v = member
            if isinstance(v, FieldBase):
                i_names[v] = name
        # ...keep order of fields
        old_names = self.fields.copy()
        self.fields.clear()
        for n, v in old_names.items():
            if v.consumed_by:
                v = v.consumed_by  # wrapped by another field
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
        # ...set minimum tail bit length
        min_tail = 0
        for f in reversed(self.fields.values()):
            f.offset.min_tail_length = min_tail
            if f.fixed_bit_length >= 0:
                min_tail += f.fixed_bit_length

    def __repr__(self) -> str:
        r = []
        for n, f in self.fields.items():
            r.append(f"{n}: {f}")
        return "\n".join(r)


class FieldPath(FieldPointer[F, T]):
    def __init__(self, start: FieldBase[F, T]):
        self.path = [start]

    def __truediv__(self, other: FieldBase[Any, T]) -> 'FieldPath':
        self.path.append(other)
        return self

    def get(self, frame: F) -> T:
        if frame.backend.structure.is_field_here(self.path[0]):
            # resolve path
            v = frame
            for i, p in enumerate(self.path):
                v = p.get(v)
                if (i < len(self.path) - 1) and not isinstance(v, Frame):
                    raise Exception(f"Bad field {p.field_name} in path: " + "/".join([p.field_name for p in self.path]))
            return v
        elif frame.backend.parent:
            return self.get(frame.backend.parent.frame)
        return None


class LayerMapping:
    """Map lower layer selector into upper layer payload"""
    def __init__(self, payload: FieldBase):
        self._mappings: Dict[FieldBase, Dict[FieldPointer, Dict]] = {
            payload: {}
        }
        self._payload = payload

    def by(self, type_field: FieldPointer[Any, T], mappings: typing.Dict[T, Type[Frame]]) -> Self:
        """Add mappings for defined payload"""
        mp = self._mappings[self._payload]
        mp.setdefault(type_field, {}).update(mappings)
        return self

    def get_mappings(self, payload: FieldBase) -> Dict[FieldPointer, Dict[Any, Type[Frame]]]:
        """Get mappings for a payload, if any"""
        return self._mappings.get(payload) or {}

    def add_to(self, frame: F) -> F:
        """Add mappings to a frame"""
        frame.backend.add_mapping(self)
        return frame
