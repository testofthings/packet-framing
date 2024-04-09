import inspect
import typing
from typing import Optional, Callable, List, Type, Any, Dict, Self

from framing.codecs import IntegerCodec, IntegerFormat, ValueCodec
from framing.raw_data import Raw, RawData, LengthEntity

# Frame type
F = typing.TypeVar("F", bound='Frame')

# Field value type
T = typing.TypeVar("T")


class EncodingState:
    """Encoding state"""
    pass


class FieldOffset:
    def __init__(self, field: Optional['Field'] = None):
        self.prefix: Optional[FieldOffset] = None
        self.field: Optional[Field] = field
        self.fixed_bit_offset = 0
        self.min_tail_length = 0

    def __repr__(self):
        r = []
        if self.prefix:
            r.append(f"{self.prefix}")
        r.append(f"{self.fixed_bit_offset}")
        if self.field:
            r.append(self.field.field_name)
        return " + ".join(r)


class Calculator:
    """Integer value calculator"""
    def __init__(self, next_step: Optional['Calculator']):
        self.next_step = next_step

    def pull(self, backend: 'FrameBackend') -> float:
        """Pull value from source"""
        return self.next_step.pull(backend)

    def push(self, backend: 'FrameBackend', value: float) -> float:
        """Push value to source"""
        return self.next_step.push(backend, value)


class FieldPointer(typing.Generic[F, T]):
    """Path pointing to a field"""
    def get(self, frame: 'Frame') -> T:
        raise NotImplementedError()


class Field(FieldPointer[F, T]):
    """Base class for fields"""
    def __init__(self, type_name: str, default_value: T, fixed_bit_offset=-1):
        self.field_name = "field?"
        self.type_name = type_name
        self.default_value = default_value
        self.fixed_bit_offset = fixed_bit_offset
        self.fixed_bit_length = -1
        self.max_bit_length = -1
        self.min_bit_length = -1
        self.direct_decode = False
        self.offset = FieldOffset(self)
        self.structure: Optional['Structure'] = None  # set by structure herself
        self.end_offset_resolver: Optional[Calculator] = None
        self.length_resolver: Optional[Calculator] = None
        self.consumed_by: Optional[Field[F, Any]] = None

    def get(self, frame: F) -> T:
        return frame.backend.get(self)

    def get_choice(self, frame: F) -> T:
        """Return the selected choice, when this is a selection field, otherwise the value itself"""
        v = self.get(frame)
        if v.backend.choice:
            return v.backend.choice.get(v)
        return v

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

    def _validate_length(self, bit_length: int) -> int:
        """Validate bit length against minimum and maximum lengths, raise error if too short"""
        if self.min_bit_length >= 0 and bit_length < self.min_bit_length:
            raise EOFError(f"Field '{self.field_name}' too short: {bit_length} < {self.min_bit_length} bits")
        if self.max_bit_length > 0:
            bit_length = min(bit_length, self.max_bit_length)
        return bit_length

    def get_bit_length(self, frame: F) -> int:
        """Get bit length for a value"""
        v = frame.backend.get(self)
        return self.encoding_bit_length(frame.backend, v)

    def as_frame(self, frame: F, frame_type: Optional[Type[F]] = None, default_frame=True) -> Optional['Frame']:
        """Return value as frame, use type information when available"""
        return frame.backend.get_as_frame(self, frame_type, default_frame)

    def as_raw(self, frame: F) -> Optional[RawData]:
        """Get as raw, do not try to attempt to parse payload. Does not work, if payload determines the length"""
        return frame.backend.get_raw(self)[0]

    def to_string(self, frame: F) -> str:
        """A string representation of current value, for unit tests"""
        enc = self.encode(self.get(frame), EncodingState())
        return f"{enc}"

    def __repr__(self):
        return f"{self.field_name}: {self.type_name}"

    def __lt__(self, other: 'Field') -> bool:
        return self.field_name < other.field_name

    # Methods for access by backend

    def encoding_bit_length(self, backend: 'FrameBackend', value: T) -> int:
        """Resolve encoding length for a value"""
        raise NotImplementedError()

    def encode(self, value: T, state: EncodingState) -> RawData:
        """Encode a value"""
        raise NotImplementedError()

    def decode_bit_length(self, data: RawData, bit_offset: int, value: Optional[T], backend: 'FrameBackend') -> int:
        """Resolve bit length on decoding, value is provided if known"""
        if self.fixed_bit_length >= 0:
            return self.fixed_bit_length
        # variable length field
        bit_length = -1
        if self.end_offset_resolver:
            # end offset resolver
            bit_length = int(self.end_offset_resolver.pull(backend)) - bit_offset
        elif self.length_resolver:
            # field length resolver
            bit_length = int(self.length_resolver.pull(backend))
        return bit_length

    def decode(self, data: RawData, bit_length: int, backend: 'FrameBackend') -> T:
        """Decode value. Bit length is provided if it is resolved earlier and available"""
        raise NotImplementedError()

    def decode_direct(self, frame_data: RawData, backend: 'FrameBackend') -> T:
        """Decode value directly from frame data. Called when direct decode is true"""
        raise NotImplementedError()


class FrameBackend:
    """Base class for frame backend"""
    def __init__(self, frame: 'Frame'):
        self.frame = frame
        self.is_decoder = False
        self.structure = FrameStructure.get_struct(frame)
        if not self.structure.built:
            self.structure.finish_building(frame)
        self.choice: Optional[Field] = self.structure.get_field_by() if self.structure.is_selection else None
        self.parent: Optional[FrameBackend] = None

    def structure_name(self) -> str:
        return self.structure.structure_name

    def get(self, field: Field[F, T]) -> T:
        raise NotImplementedError()

    def set(self, field: Field[F, T], value: T) -> Self:
        raise NotImplementedError("Editing not allowed with this backend")

    def get_item(self, sequence_field: Field, item_field: Field[F, T], index: int):
        raise NotImplementedError()

    def iterate(self, sequence_field: Field, item_field: Field[F, T],
                count=-1, terminator: Optional[Callable[[T], bool]] = None) -> typing.Iterator[T]:
        """Iterate sequence field values without storing them"""
        raise NotImplementedError()

    def get_raw(self, field: Field) -> typing.Tuple[RawData, int]:
        """Get field raw data"""
        raise NotImplementedError()

    def get_as_frame(self, field: Field[F, T], frame_type: Optional[Type[F]] = None,
                     default_frame=True) -> Optional['Frame']:
        """Get field value as frame, use implicit or explicit type"""
        raise NotImplementedError()

    def decode_as_frame(self, mapping: Dict[FieldPointer, Dict[Any, Type['Frame']]], data: RawData) -> 'Frame':
        """Decore raw field as a frame with given mappings"""
        raise NotImplementedError()

    def factory(self, decode: RawData = None) -> Callable[['Frame'], 'FrameBackend']:
        """Create a fresh backend for given frame"""
        raise NotImplementedError()

    def get_bit_offset(self, offset: FieldOffset) -> int:
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

    def close(self) -> Self:
        """Close underlying open files if any"""
        return self


TF = typing.TypeVar("TF", bound='Frame')


class Frame(LengthEntity):
    """Base class for frames"""
    def __init__(self, backend_factory: Callable[['Frame'], FrameBackend]):
        self.backend = backend_factory(self)

    def bit_length(self) -> int:
        return self.backend.get_bit_length()

    def byte_length(self) -> int:
        return self.backend.get_bit_length() // 8

    def encode(self) -> RawData:
        """Encode the frame into bytes"""
        return self.backend.encode()

    def __truediv__(self, field: Field[Self, TF]) -> TF:
        return field.as_frame(self)

    def __repr__(self):
        return self.backend.__repr__()


class FrameStructure(typing.Generic[F]):
    """Frame structure definition"""
    def __init__(self):
        self.structure_name = "Unnamed"
        self.is_selection = False
        self.fields: typing.Dict[str, Field] = {}
        self.fields_fixed_bit_offset = 0
        self.fields_length = FieldOffset()
        self.commit_procedures: List[typing.Tuple[Optional[Field], Callable[[F], None]]] = []
        self.built = False

    def field(self, field: Field) -> Field:
        raise NotImplementedError()

    def commit(self, frame: F):
        for cp in self.commit_procedures:
            cp[1](frame)

    @classmethod
    def get_struct(cls, frame_type: F) -> 'FrameStructure[F]':
        if hasattr(frame_type, "structure_"):
            return getattr(frame_type, "structure_")  # underscored to avoid naming collision
        return getattr(frame_type, "structure")

    def is_field_here(self, field: Field) -> bool:
        f = self.fields.get(field.field_name)
        return f == field

    def get_field_by(self, key=None) -> Field[F, Any]:
        """The field by key or the default field, used for selections"""
        if key is not None:
            f = self.fields.get(key)
            if f:
                return f
        return self.fields.values().__iter__().__next__()

    def _get_a_name(self, override: Optional[str]) -> str:
        """Get name or temporary name for a field"""
        return override if override else f"__{len(self.fields)}"

    def finish_building(self, frame: F):
        # find field names
        self.structure_name = type(frame).__name__
        i_names: typing.Dict[Field, str] = {}
        all_members = inspect.getmembers(frame)
        for member in all_members:
            name, v = member
            if isinstance(v, Field):
                i_names[v] = name
        # ...keep order of fields
        old_names = self.fields.copy()
        assert old_names, f"No fields defined for Selection '{self.structure_name}'"
        self.fields.clear()
        for n, v in old_names.items():
            while v.consumed_by:
                v = v.consumed_by  # wrapped by another field
            nn = i_names[v] if n.startswith("__") else n
            self.fields[nn] = v
            v.field_name = nn
        self._resolve_offsets()
        self.built = True

    def _resolve_offsets(self):
        """Resolve offsets"""
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


class LayerMapping:
    """Map lower layer selector into upper layer payload"""
    def __init__(self, payload: Field = None, base: Optional['LayerMapping'] = None):
        assert not (payload and base), "Cannot provide both payload and base mapping"
        self._mappings: Dict[Field, Dict[FieldPointer, Dict]] = {}
        self._payload = payload
        if payload:
            self._mappings[payload] = {}
        if base is not None:
            self._payload = base._payload
            base.merge(self)

    def resolve_payload_type(self, frame: Frame, field: Field) -> Type[Frame]:
        """Resolve payload type, return raw frame if no mapping found"""
        layer_map = self.get_mappings(field)
        assert layer_map, f"No known payload mapping for {field}"
        for type_f, m in layer_map.items():
            type_v = type_f.get(frame)
            p_type = m.get(type_v)
            if p_type is not None:
                return p_type
        from framing.backends import RawFrame
        return RawFrame

    def decode_payload(self, frame: Frame, field: Field, data: Optional[RawData] = None) -> Frame:
        """Resolve payload type and decode the frame using this mapping"""
        layer_map = self.get_mappings(field)
        assert layer_map, f"No known payload mapping for {field}"
        be = frame.backend
        if data is None:
            data = be.get_raw(field)[0]
        return be.decode_as_frame(layer_map, data)

    def by(self, type_field: FieldPointer[Any, T], mappings: typing.Dict[T, Type[Frame]]) -> Self:
        """Add mappings for defined payload"""
        mp = self._mappings[self._payload]
        mp.setdefault(type_field, {}).update(mappings)
        return self

    def many_by(self, fields: Dict[Field, FieldPointer[Any, T]], mappings: typing.Dict[T, Type[Frame]]) -> Self:
        """Add mappings for defined payload for many type fields"""
        first = True
        t_map = self._mappings.get(self._payload, {}).values()
        for pf, tf in fields.items():
            if first:
                self._payload = pf
            mp = self._mappings.setdefault(pf, {})
            nt_map = mp.setdefault(tf, {})
            nt_map.update(mappings)
            for tm in t_map:
                nt_map.update(tm)
        return self

    def is_mapped(self, payload: Field) -> bool:
        """Is payload mapped?"""
        return payload in self._mappings

    def get_mappings(self, payload: Field) -> Optional[Dict[FieldPointer, Dict[Any, Type[Frame]]]]:
        """Get mappings for a payload, if any"""
        return self._mappings.get(payload)

    def add_to(self, frame: F) -> F:
        """Add mappings to a frame"""
        frame.backend.add_mapping(self)
        return frame

    def merge(self, mapping: 'LayerMapping') -> Self:
        """Merge mappings with other mapping object"""
        for f, mm in self._mappings.items():
            mapping._mappings.setdefault(f, {}).update(mm)
        return self

    def __add__(self, other: 'LayerMapping') -> 'LayerMapping':
        """Add layer mappings to a fresh mapping (slower way, use with care)"""
        m = LayerMapping()
        self.merge(m)
        other.merge(m)
        return m
