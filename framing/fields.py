import enum
from typing import Iterator

from framing.base import *
from framing.base import Field, FrameBackend
from framing.raw_data import RawData


class Multiplier(Calculator):
    """Multiply (or divide) the value"""
    def __init__(self, multiplier: float, next_step: Calculator):
        super().__init__(next_step)
        self.multiplier = multiplier

    def pull(self, backend: FrameBackend) -> float:
        return self.next_step.pull(backend) * self.multiplier

    def push(self, backend: FrameBackend, value: float) -> float:
        return self.next_step.push(backend, value / self.multiplier)


class CopyToField(Calculator):
    """Copy value to other field on push"""
    def __init__(self, field: 'IntField', next_step: Calculator):
        super().__init__(next_step)
        self.field = field

    def push(self, backend: FrameBackend, value: float) -> float:
        backend.set(self.field, int(value))
        return self.next_step.push(backend, value)


class FieldOffsetValue(Calculator):
    """Get field offset value"""
    def __init__(self, field: Field):
        super().__init__(None)
        self.field = field

    def pull(self, backend: FrameBackend) -> float:
        return backend.get_bit_offset(self.field.offset)


class FieldLengthByTerminator(Calculator):
    """Get field offset value"""
    def __init__(self, field: Field, terminator: RawData):
        super().__init__(None)
        self.field = field
        assert terminator.bit_length() == 8, "Only supporting 8-bit terminators"
        self.terminator = terminator.octet(0)

    def pull(self, backend: FrameBackend) -> float:
        f_off = backend.get_bit_offset(self.field.offset) // 8
        data = backend.input_data()
        v = data.octet(f_off)
        while v != -1:
            f_off += 1
            if v == self.terminator:
                break
            v = data.octet(f_off)
        return f_off * 8


class PaddingValue(Calculator):
    """Get padding value, next step calculates padded length"""
    def __init__(self, target_length: int, next_step: Calculator):
        super().__init__(next_step)
        self.target_length = target_length * 8  # target_length in bytes

    def pull(self, backend: FrameBackend) -> float:
        if backend.is_decoder:
            # No padding on decoding
            return 0
        value = self.next_step.pull(backend)
        len_v = max(0, self.target_length - int(value))
        return len_v


class CalculatorSource:
    def calculator(self) -> Calculator:
        raise NotImplementedError()


class ValueOf(CalculatorSource):
    """Get value from the given field"""
    def __init__(self, field: 'FieldPointer[Any, int]'):
        if isinstance(field, IntField):
            self.end: Calculator = field
        else:
            self.end: Calculator = ValueFromPath(field)

    def calculator(self) -> Calculator:
        return self.end

    def __mul__(self, value: float) -> 'ValueOf':
        self.end = Multiplier(value, self.end)
        return self

    def __truediv__(self, value: float) -> 'ValueOf':
        self.end = Multiplier(1 / value, self.end)
        return self

    def copy_to(self, field: 'IntField') -> Self:
        self.end = CopyToField(field, self.end)
        return self


class FieldPath(FieldPointer[Frame, T], CalculatorSource):
    def __init__(self, start: Field):
        self.path = [start]

    def __truediv__(self, other: Field[Any, T]) -> 'FieldPath[T]':
        self.path.append(other)
        return self

    def calculator(self) -> Calculator:
        return ValueFromPath(self)

    def get(self, frame: Frame) -> T:
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


class ValueFromPath(Calculator):
    def __init__(self, pointer: FieldPointer[Frame, int]):
        super().__init__(None)
        self.pointer = pointer

    def pull(self, backend: 'FrameBackend') -> float:
        return self.pointer.get(backend.frame)

    def push(self, backend: 'FrameBackend', value: float) -> float:
        raise NotImplementedError()


FT = typing.TypeVar("FT", bound=Frame)
V = typing.TypeVar("V")


class ConfigurableField(Field[F, T]):

    def __truediv__(self, other: 'Field[Any, T]') -> 'FieldPath':
        return FieldPath(self) / other

    def of(self, location: FieldPointer) -> FieldPath[T]:
        if isinstance(location, FieldPath):
            return location / self
        elif isinstance(location, Field):
            return FieldPath(location) / self
        else:
            raise Exception(f"Cannot construct path from: {location}")

    def length_by(self, value: CalculatorSource) -> Self:
        self.length_resolver = Multiplier(8, value.calculator())
        field = self

        def procedure(frame: F):
            v = frame.backend.get(field)
            f_len = field.encoding_bit_length(frame.backend, v)
            field.length_resolver.push(frame.backend, f_len)
        # call at commit to push length
        self.structure.commit_procedures.append((self, procedure))
        return self

    def terminator(self, value: RawData) -> Self:
        self.end_offset_resolver = FieldLengthByTerminator(self, value)
        return self

    def end_offset_by(self, value: CalculatorSource) -> Self:
        calc = Multiplier(8, value.calculator())
        self.end_offset_resolver = calc
        field = self

        def procedure(frame: F):
            v = frame.backend.get(field)
            f_off = frame.backend.get_bit_offset(field.offset)
            f_len = field.encoding_bit_length(frame.backend, v)
            field.end_offset_resolver.push(frame.backend, f_off + f_len)
        # call at commit to push length
        self.structure.commit_procedures.append((self, procedure))
        return self

    def pad_to(self, min_offset: int):
        calc = FieldOffsetValue(self)
        calc = PaddingValue(min_offset, calc)
        self.length_resolver = calc
        field = self

        def procedure(frame: F):
            pad_to = int(calc.pull(frame.backend))
            frame.backend.set(field, Raw.zeroes(bit_length=pad_to))

        self.structure.commit_procedures.append((self, procedure))
        return self

    def at_commit(self, procedure: Callable[[F], T]) -> Self:
        field = self

        def commit_proc(frame: F):
            value = procedure(frame)
            frame.backend.set(field, value)

        self.structure.commit_procedures.append((self, commit_proc))
        return self


class RawField(ConfigurableField[F, RawData]):
    """Raw data field"""
    def __init__(self, default_value: RawData, min_bit_length=-1, max_bit_length=-1, fixed_bit_offset=-1):
        super().__init__("raw", default_value, fixed_bit_offset)
        self.max_bit_length = max_bit_length
        self.min_bit_length = min_bit_length
        if max_bit_length == min_bit_length and max_bit_length > 0:
            # fixed length field
            self.fixed_bit_length = min_bit_length
            self.direct_decode = self.fixed_bit_offset >= 0 and self.fixed_bit_length >= 0

    def get(self, frame: F) -> RawData:
        v = frame.backend.get(self)
        if isinstance(v, Frame):
            # payload can be a frame
            return v.encode()
        return v

    def __getitem__(self, frame: F) -> RawData:
        return self.get(frame)

    def process_frame(self, frame: F, procedures: Dict[Type[Frame], Callable[[Any], V]]) -> Optional[V]:
        """Process frame here differentiating by frame type"""
        v = self.as_frame(frame, default_frame=False)
        proc = procedures.get(type(v))
        return proc(v) if proc else None

    def get_bit_length(self, frame: F) -> int:
        """Get bit length for a value"""
        v = frame.backend.get(self)
        return v.bit_length()

    def encoding_bit_length(self, backend: FrameBackend, value: RawData) -> int:
        return value.bit_length()

    def encode(self, value: RawData, state: EncodingState) -> RawData:
        return value

    def decode_bit_length(self, data: RawData, bit_offset: int, value: Optional[RawData],
                          backend: 'FrameBackend') -> int:
        if value is not None:
            return value.bit_length()  # Pst... value could be Frame, as well
        bit_len = super().decode_bit_length(data, bit_offset, None, backend)
        if bit_len >= 0 and self.min_bit_length < self.max_bit_length:
            # variable length, check limits
            bit_len = self._validate_length()
        return bit_len

    def decode(self, data: RawData, bit_length: int, backend: FrameBackend) -> RawData:
        if self.fixed_bit_length >= 0:
            return data.subBlockBits(0, self.fixed_bit_length)
        if bit_length >= 0:
            return data.subBlockBits(0, bit_length)
        if self.min_bit_length < self.max_bit_length:
            # variable length, check find out how much to read
            avail = data.bits_available()
            if avail >= self.max_bit_length:
                # maximum amount of data available
                return data.subBlockBits(0, self.max_bit_length)
            # less than maximum surely available, must read to find out
            data_len = data.bit_length()
            dec_len = self._validate_length(data_len)
            return data.subBlockBits(0, dec_len)
        return data  # read it all

    def decode_direct(self, frame_data: RawData, backend: FrameBackend) -> RawData:
        v = frame_data.subBlockBits(self.fixed_bit_offset, self.fixed_bit_length)
        return v


class IntField(ConfigurableField[F, int], Calculator, CalculatorSource):
    """Integer field"""
    def __init__(self, codec: IntegerCodec, default_value: int, fixed_bit_offset: int):
        super().__init__("int", default_value)
        self.codec = codec
        self.fixed_bit_length = codec.get_fixed_bit_length()
        self.fixed_bit_offset = fixed_bit_offset
        if fixed_bit_offset >= 0 and self.fixed_bit_length >= 0:
            # fixed integer in fixed offset - fast value decode from frame data
            self.direct_decode = True

    def flag_values(self, definition: Type[enum.IntFlag]) -> Self:
        return self

    def encoding_bit_length(self, backend: FrameBackend, value: int) -> int:
        return self.codec.get_bit_length(value)

    def encode(self, value: int, state: EncodingState) -> RawData:
        return self.codec.encode(value)

    def decode_bit_length(self, data: RawData, bit_offset: int, value: Optional[int],
                          backend: 'FrameBackend') -> int:
        if value is not None:
            return self.codec.get_bit_length(value)
        return super().decode_bit_length(data, bit_offset, None, backend)

    def decode(self, data: RawData, bit_length: int, backend: FrameBackend) -> int:
        v = self.codec.decode(data)
        return v

    def decode_direct(self, frame_data: RawData, backend: FrameBackend) -> int:
        v = self.codec.decode_direct(self.fixed_bit_offset, frame_data)
        return v

    def calculator(self) -> Calculator:
        return self

    def pull(self, backend: FrameBackend) -> float:
        # NOTE: Looks like marginal/non-existent improvement
        # if self.direct_decode and backend.is_decoder:
        #     # take the shortcut, we are decoding, thus raw data should be available
        #     raw = backend.input_data()
        #     r = self.codec.decode_direct(self.fixed_bit_offset, raw)
        # else:
        r = backend.get(self)
        return r

    def push(self, backend: FrameBackend, value: float) -> float:
        backend.set(self, int(value))
        return value


class SubStructureField(ConfigurableField[F, FT]):
    """Sub-frame field"""
    def __init__(self, sub_type: Type[FT]):
        super().__init__("sub", None)
        self.sub_type = sub_type
        self.sub_structure = Structure.get_struct(sub_type)
        self.choice_resolver: Optional[Calculator] = None

    def choice_by(self, value: CalculatorSource) -> Self:
        """Configure the choice in field by given value"""
        assert isinstance(Structure.get_struct(self.sub_type), Selection), \
            f"Structure {Structure.get_struct(self.sub_type).structure_name} is not a selection"
        choice_resolver = value.calculator()
        self.choice_resolver = choice_resolver

        def proc(f: Frame):
            choice = self.get(f)
            sel = typing.cast(Selection, choice.structure)
            key = sel.reverse_map.get(choice.backend.structure, 0)
            choice_resolver.push(f.backend, key)

        self.structure.at_commit(proc)
        return self

    def select(self, frame: F, field: ConfigurableField[FT, Any]) -> FT:
        sub = self.sub_type(frame.backend.factory())
        sub.backend.choice = field
        frame.backend.set(self, sub)
        return sub

    def process_frame(self, frame: F, procedures: Dict[Type, Callable[[Any], V]]) -> Optional[V]:
        """Process frame here differentiating by frame type"""
        v = self.get(frame)
        if v.structure.is_selection:
            # let's assume that the selection choices are the keys
            field = v.backend.choice
            proc = procedures.get(field)
            if proc:
                v = field.get(v)
        else:
            proc = procedures.get(type(v))
        return proc(v) if proc else None

    def get_default_value(self, frame: F) -> FT:
        return self.sub_type(frame.backend.factory())

    def encoding_bit_length(self, backend: FrameBackend, value: FT) -> int:
        return value.bit_length()

    def encode(self, value: FT, state: EncodingState) -> RawData:
        enc = value.encode()
        return enc

    def decode_bit_length(self, data: RawData, bit_offset: int, value: Optional[FT], backend: 'FrameBackend') -> int:
        if value is not None:
            return value.bit_length()
        b_len = super().decode_bit_length(data, bit_offset, None, backend)
        if b_len >= 0:
            return b_len
        # if self.choice_resolver: ... not trying to resolve, as we would need to create the backend for it
        v = self.decode(data.tailBits(bit_offset), -1, backend)
        return v.bit_length()

    def decode(self, data: RawData, bit_length: int, backend: FrameBackend) -> FT:
        sub_f = self.sub_type(backend.factory(decode=data))
        if self.choice_resolver:
            # make the choice
            key = self.choice_resolver.pull(backend)
            sub_field = sub_f.backend.structure.get_field_by(key)
            sub_f.backend.choice = sub_field
        return sub_f


class LengthOfLV(Calculator):
    def __init__(self, field: 'LVField'):
        super().__init__(None)
        self.field = field

    def pull(self, backend: 'FrameBackend') -> float:
        bit_off = backend.get_bit_offset(self.field.offset)
        data = backend.input_data().subBlockBits(0, bit_off)
        return self.field.length_codec.decode(data)


class LVField(ConfigurableField[F, T]):
    """Field with length prefix"""
    def __init__(self, sub: Field[F, T], length=IntegerFormat()):
        super().__init__("LV", [])
        self.sub = sub
        self.structure = sub.structure
        self.length_codec = length.create_codec()
        if self.length_codec.get_fixed_bit_length() < 0:
            raise Exception("Variable-length length in LV not supported, now")
        self.length_resolver = LengthOfLV(self)
        sub.consumed_by = self

    def encoding_bit_length(self, backend: FrameBackend, value: T) -> int:
        len_len = self.length_codec.get_fixed_bit_length()
        v_len = self.sub.encoding_bit_length(backend, value)
        return len_len + v_len

    def encode(self, value: T, state: EncodingState) -> RawData:
        value_r = self.sub.encode(value, state)
        len_v = value_r.byte_length()  # NOTE: How to add calculations here (no backend)?
        len_r = self.length_codec.encode(len_v)
        return len_r + value_r

    def decode(self, data: RawData, bit_length: int, backend: FrameBackend) -> T:
        d_len = self.length_codec.decode(data) * 8
        d_data = data.subBlockBits(self.length_codec.get_fixed_bit_length(), d_len)
        return self.sub.decode(d_data, -1, backend)

    def decode_bit_length(self, data: RawData, bit_offset: int, value: T, backend: 'FrameBackend') -> int:
        l_data = data.tailBits(bit_offset)
        d_len = self.length_codec.decode(l_data) * 8
        return self.length_codec.get_fixed_bit_length() + d_len

    def pull(self, backend: FrameBackend) -> float:
        return backend.get(self.sub)

    def push(self, backend: FrameBackend, value: float):
        backend.set(self.sub, value)


class FrameIterator(Iterator[FT]):
    """Frame iterator"""
    def __init__(self, source: Iterator[FT]):
        self.source = source

    def field(self, field: ConfigurableField[FT, T], as_frame=False) -> 'FieldIterator[T]':
        i = FieldIterator(field, self.source)
        i.frame_value = as_frame
        return i

    def __next__(self) -> FT:
        return self.source.__next__()


class FieldIterator(typing.Generic[F, T], Iterator[T]):
    def __init__(self, field: ConfigurableField[F, T], source: Iterator[T]):
        self.it_field = field
        self.source = source
        self.frame_value = False

    def field(self, field: ConfigurableField[FT, T], as_frame=False) -> 'FieldIterator[T]':
        self.frame_value = True
        i = FieldIterator(field, self)
        i.frame_value = as_frame
        return i

    def __next__(self) -> FT:
        f = self.source.__next__()
        v = self.it_field.as_frame(f) if self.frame_value else self.field.get(f)
        while v is None:
            f = self.source.__next__()
            v = self.it_field.as_frame(f) if self.frame_value else self.field.get(f)
        return v


class Sequence(ConfigurableField[F, List[FT]]):
    """Field of sequence of values"""
    def __init__(self, sub: Field[F, FT]):
        super().__init__("sequence", [])
        self.sub = sub
        self.structure = sub.structure
        self.item_frame: Optional[Type[FT]] = None
        if isinstance(sub, SubStructureField):
            self.item_frame = sub.sub_type
            self.item_fixed_bit_length = -1  # Note: Structure should support this!
        else:
            self.item_fixed_bit_length = self.sub.fixed_bit_length
        self.count_resolver: Optional[Calculator] = None
        self.terminator_call: Optional[Callable[[FT], bool]] = None
        sub.consumed_by = self

    def count_by(self, value: CalculatorSource) -> Self:
        self.count_resolver = value.calculator()
        return self

    def terminator_test(self, test: Callable[[Any], bool]) -> Self:
        self.terminator_call = test
        return self

    def iterate(self, frame: F) -> FrameIterator[FT]:
        """Get item by index"""
        known_count = int(self.count_resolver.pull(frame.backend)) if self.count_resolver else -1
        s = frame.backend.iterate(self, self.sub, known_count, self.terminator_call)
        return FrameIterator(s)

    def get_count(self, frame: F) -> int:
        if self.count_resolver:
            return int(self.count_resolver.pull(frame.backend))
        # horrible way...
        c = 0
        it = self.iterate(frame)
        for _ in it:
            c += 1
        return c

    def item(self, frame: F, index: int) -> FT:
        return frame.backend.get_item(self, self.sub, index)

    def set_repeat(self, frame: F, count: int) -> List[F]:
        """Set value by repeating item given times"""
        v = []
        for _ in range(0, count):
            v.append(self.sub.get_default_value(frame))
        frame.backend.set(self, v)
        return v

    def get_default_value(self, frame: F) -> List[FT]:
        return []

    def encoding_bit_length(self, backend: FrameBackend, value: List[FT]) -> int:
        if self.sub.fixed_bit_length >= 0:
            return self.sub.fixed_bit_length * len(value)
        b_len = 0
        for v in value:
            b_len += self.sub.encoding_bit_length(backend, v)
        # Note: terminator must be in the list
        return b_len

    def encode(self, value: List[FT], state: EncodingState) -> RawData:
        r = []
        for v in value:
            r.append(self.sub.encode(v, state))
        # Note: terminator must be in the list
        return Raw.sequence(r)

    def decode_bit_length(self, data: RawData, bit_offset: int, value: List[FT], backend: 'FrameBackend') -> int:
        if value is not None:
            known_count = len(value)
        else:
            known_count = int(self.count_resolver.pull(backend)) if self.count_resolver else -1

        if known_count == 0 or (known_count >= 0 and self.fixed_bit_length >= 0):
            return known_count * self.sub.fixed_bit_length

        b_len = super().decode_bit_length(data, bit_offset, None, backend)
        if b_len >= 0:
            return b_len

        if known_count < 0 and self.terminator_call is None:
            return -1  # we decode everything...

        # The hard way...
        i = 0
        b_off = 0
        while True:
            if 0 <= known_count <= i:
                break
            b_data = data.tailBits(bit_offset + b_off)
            if b_data.octet(0) < 0:
                break  # no more data to read
            i_value = None if value is None else value[i]
            v_len = self.sub.decode_bit_length(b_data, 0, i_value, backend)
            assert v_len >= 0, "Sequence sub-value must know its length"
            b_off += v_len
            if self.terminator_call is not None:
                v = self.sub.decode(b_data, v_len, backend)
                if self.terminator_call(v):
                    break
            i += 1
        return b_off

    def decode(self, data: RawData, bit_length: int, backend: FrameBackend) -> List[FT]:
        known_count = int(self.count_resolver.pull(backend)) if self.count_resolver else -1
        items = []
        previous = None
        while True:
            if 0 <= known_count <= len(items):
                break
            if previous is not None:
                v_len = self.sub.decode_bit_length(data, 0, previous, backend)
                data = data.tailBits(v_len)
            if data.octet(0) < 0:
                break  # no more data to read
            v = self.sub.decode(data, -1, backend)
            items.append(v)  # Add terminator to the list
            if self.terminator_call is not None and self.terminator_call(v):
                break
            previous = v
        return items


class Structure(FrameStructure[F]):
    """Frame structure definition"""

    def _update_fixed_length(self, field: Field):
        """Update fixed length or reset it to -1"""
        if self.fields_fixed_bit_offset < 0 or field.fixed_bit_length < 0:
            self.fields_fixed_bit_offset = -1
        else:
            self.fields_fixed_bit_offset += field.fixed_bit_length

    def field(self, field: Field, name: str = None) -> Field:
        fn = self._get_a_name(name)
        field.structure = self
        self.fields[fn] = field
        self._update_fixed_length(field)
        return field

    def raw(self, bits: int = None, bytes: int = None, min_bits: int = None, min_bytes: int = None, default: RawData = None,
            name: str = None) -> RawField[F]:
        fn = self._get_a_name(name)
        fix_len = -1
        if bits is not None:
            fix_len = bits
        if bytes is not None:
            fix_len = bytes * 8
        min_len = fix_len
        if min_bits is not None:
            min_len = min_bits
        if min_bytes is not None:
            min_len = min_bytes * 8
        assert min_len <= fix_len, f"Minimun length is {min_len} bits and max length is {fix_len} bits"
        if default is None:
            default = Raw.empty if min_len < 0 else Raw.zeroes(bit_length=min_len)
        f: RawField[F] = RawField(default, min_len, fix_len, self.fields_fixed_bit_offset)
        f.structure = self
        self.fields[fn] = f
        self._update_fixed_length(f)
        return f

    def integer(self, int_format=IntegerFormat(), bytes=-1, bits=-1,
                default=0, name: str = None) -> IntField[F]:
        fn = self._get_a_name(name)
        if bytes > 0:
            int_format = int_format.bytes(bytes)
        if bits > 0:
            int_format = int_format.bits(bits)
        codec = int_format.create_codec()
        f = IntField(codec, default, fixed_bit_offset=self.fields_fixed_bit_offset)
        f.structure = self
        self.fields[fn] = f
        self._update_fixed_length(f)
        return f

    def sub(self, sub_frame: Type[FT], name: str = None) -> SubStructureField[F, FT]:
        fn = self._get_a_name(name)
        f = SubStructureField(sub_frame)
        f.structure = self
        self.fields[fn] = f
        self._update_fixed_length(f)
        return f

    def at_commit(self, update: Callable[[F], None]):
        self.commit_procedures.append((None, update))


class Selection(Structure[F]):
    """A frame which only the chosen field is present"""
    def __init__(self):
        super().__init__()
        self.is_selection = True
        self.choice_map: Dict[Any, ConfigurableField] = {}
        self.reverse_map: Dict[Structure, Any] = {}

    def _update_fixed_length(self, field: Field):
        self.fields_fixed_bit_offset = 0  # all choices start from offset 0

    def choice(self, key, value: ConfigurableField[F, T]) -> ConfigurableField[F, T]:
        if key in self.choice_map or value in self.reverse_map:
            raise Exception(f"Duplicate entry for key {key}")
        assert isinstance(value, ConfigurableField), "Provide a field for choice(...)"
        self.choice_map[key] = value
        self.reverse_map[value.structure] = key
        return value

    def get_field_by(self, key=None) -> Field[F, Any]:
        if key is not None:
            f = self.choice_map.get(key)
            if f:
                return f
        return super().get_field_by(key)

    def _resolve_offsets(self):
        pass  # all zeroes ok

