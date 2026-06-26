"""Field implementations"""

from abc import ABC
import enum
from typing import Iterator, Optional, Dict, TypeVar, Self, Type, cast, Callable, List, Any

from framing.base import *
from framing.base import Field, FrameBackend
from framing.codecs import IntegerCodec, IntegerFormat
from framing.raw_data import RawData, Raw


class Multiplier(Calculator):
    """Multiply (or divide) the value"""
    def __init__(self, multiplier: float, next_step: Calculator):
        super().__init__(next_step)
        self.multiplier = multiplier

    def pull(self, backend: FrameBackend) -> float:
        assert self.next_step, "Multiplier must have next step"
        return self.next_step.pull(backend) * self.multiplier

    def push(self, backend: FrameBackend, value: float) -> float:
        assert self.next_step, "Multiplier must have next step"
        return self.next_step.push(backend, value / self.multiplier)


class CopyToField(Calculator):
    """Copy value to other field on push"""
    def __init__(self, field: 'IntField[F]', next_step: Calculator):
        super().__init__(next_step)
        self.field = field

    def push(self, backend: FrameBackend, value: float) -> float:
        assert self.next_step, "CopyToField must have next step"
        backend.set(self.field, int(value))
        return self.next_step.push(backend, value)


class FieldOffsetValue(Calculator):
    """Get field offset value"""
    def __init__(self, field: AnyField):
        super().__init__(None)
        self.field = field

    def pull(self, backend: FrameBackend) -> float:
        return backend.get_bit_offset(self.field.offset)


class FieldLengthByTerminator(Calculator):
    """Get field offset value"""
    def __init__(self, field: AnyField, terminator: RawData):
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
        assert self.next_step, "PaddingValue must have next step"
        if backend.is_decoder:
            # No padding on decoding
            return 0
        value = self.next_step.pull(backend)
        len_v = max(0, self.target_length - int(value))
        return len_v


class CalculatorSource:
    """Source of calculator, for example field or field path"""
    def calculator(self) -> Calculator:
        """Get the calculator of this source"""
        raise NotImplementedError()


class ValueOf(CalculatorSource):
    """Get value from the given field"""
    def __init__(self, field: 'FieldPointer[Any, int]'):
        self.end: Calculator
        if isinstance(field, IntField):
            self.end = field
        else:
            self.end = ValueFromPath(field)

    def calculator(self) -> Calculator:
        return self.end

    def __mul__(self, value: float) -> 'ValueOf':
        self.end = Multiplier(value, self.end)
        return self

    def __truediv__(self, value: float) -> 'ValueOf':
        self.end = Multiplier(1 / value, self.end)
        return self

    def copy_to(self, field: 'IntField[F]') -> Self:
        """Copy value to other field on push"""
        self.end = CopyToField(field, self.end)
        return self


class FieldPath(FieldPointer[Frame, T], CalculatorSource):
    """Path to field, for example to get length"""
    def __init__(self, start: AnyField):
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
                    raise StructureError(
                        f"Bad field {p.field_name} in path: " + "/".join([p.field_name for p in self.path]))
            return cast(T, v)
        if frame.backend.parent:
            return self.get(frame.backend.parent.frame)
        raise ValueError(f"Field {self.path[0].field_name} not found in frame or its parents")


class ValueFromPath(Calculator):
    """Get calculation value from field path"""
    def __init__(self, pointer: FieldPointer[Frame, Any]):
        super().__init__(None)
        self.pointer = pointer

    def pull(self, backend: 'FrameBackend') -> float:
        value = self.pointer.get(backend.frame)
        if not isinstance(value, (int, float)):
            raise ValueError(f"Value from path must be int or float, got {type(value)}")
        return value

    def push(self, backend: 'FrameBackend', value: float) -> float:
        raise NotImplementedError()


V = TypeVar("V")


class ConfigurableField(Field[F, T], ABC):
    """Configurable field, base class for all fields"""
    def __init__(self, type_name: str, default_value: T | None = None, fixed_bit_offset: int = -1):
        super().__init__(type_name, default_value, fixed_bit_offset)
        self.structure: Structure[F]  # set by structure when field is added

    def __truediv__(self, other: AnyField) -> 'FieldPath[AnyFieldPointer]':
        return FieldPath(self) / other

    def of(self, location: AnyFieldPointer) -> FieldPath[T]:
        """Get field path to this field from given location"""
        if isinstance(location, FieldPath):
            return location / self
        if isinstance(location, Field):
            return FieldPath(location) / cast(AnyField, self)
        raise StructureError(f"Cannot construct path from: {location}")

    def length_by(self, value: CalculatorSource) -> Self:
        """Configure length resolver by given value"""
        length_resolver = Multiplier(8, value.calculator())
        self.length_resolver = length_resolver
        field = self

        def procedure(frame: F) -> None:
            v = frame.backend.get(field)
            f_len = field.encoding_bit_length(frame.backend, v)
            length_resolver.push(frame.backend, f_len)
        # call at commit to push length
        self.structure.commit_procedures.append((self, procedure))
        return self

    def terminator(self, value: RawData) -> Self:
        """Configure terminator for this field, for example for string fields"""
        self.end_offset_resolver = FieldLengthByTerminator(self, value)
        return self

    def end_offset_by(self, value: CalculatorSource) -> Self:
        """Configure end offset resolver by given value"""
        end_offset_resolver = Multiplier(8, value.calculator())
        self.end_offset_resolver = end_offset_resolver
        field = self

        def procedure(frame: F) -> None:
            v = frame.backend.get(field)
            f_off = frame.backend.get_bit_offset(field.offset)
            f_len = field.encoding_bit_length(frame.backend, v)
            end_offset_resolver.push(frame.backend, f_off + f_len)
        # call at commit to push length
        self.structure.commit_procedures.append((self, procedure))
        return self

    def at_commit(self, procedure: Callable[[F], T]) -> Self:
        """Set procedure to call on commit"""
        field = self

        def commit_proc(frame: F) -> None:
            value = procedure(frame)
            frame.backend.set(field, value)

        self.structure.commit_procedures.append((self, commit_proc))
        return self


class RawField(ConfigurableField[F, RawData]):
    """Raw data field"""
    def __init__(self, default_value: RawData, min_bit_length: int = -1, max_bit_length: int = -1,
                 fixed_bit_offset: int = -1) -> None:
        super().__init__("raw", default_value, fixed_bit_offset)
        self.max_bit_length = max_bit_length
        self.min_bit_length = min_bit_length
        if max_bit_length == min_bit_length and max_bit_length > 0:
            # fixed length field
            self.fixed_bit_length = min_bit_length
            self.direct_decode = self.fixed_bit_offset >= 0 and self.fixed_bit_length >= 0

    def pad_to(self, min_offset: int) -> Self:
        """Pad field to given offset"""
        calc = FieldOffsetValue(self)
        length_resolver = PaddingValue(min_offset, calc)
        self.length_resolver = length_resolver
        field = self

        def procedure(frame: F) -> None:
            pad_to = int(length_resolver.pull(frame.backend))
            padding = Raw.zeroes(bit_length=pad_to)
            frame.backend.set(field, padding)

        self.structure.commit_procedures.append((self, procedure))
        return self

    def get(self, frame: 'Frame') -> RawData:
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
        proc = procedures.get(type(v)) if v else None
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
            bit_len = self.validate_length(bit_len)
        return bit_len

    def decode(self, data: RawData, bit_length: int, backend: FrameBackend) -> RawData:
        if self.fixed_bit_length >= 0:
            return data.sub_block_bits(0, self.fixed_bit_length)
        if bit_length >= 0:
            return data.sub_block_bits(0, bit_length)
        if self.min_bit_length < self.max_bit_length:
            # variable length, check find out how much to read
            avail = data.bits_available()
            if avail >= self.max_bit_length:
                # maximum amount of data available
                return data.sub_block_bits(0, self.max_bit_length)
            # less than maximum surely available, must read to find out
            data_len = data.bit_length()
            dec_len = self.validate_length(data_len)
            return data.sub_block_bits(0, dec_len)
        return data  # read it all

    def decode_direct(self, frame_data: RawData, backend: FrameBackend) -> RawData:
        v = frame_data.sub_block_bits(self.fixed_bit_offset, self.fixed_bit_length)
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

    def flag_values(self, _definition: Type[enum.IntFlag]) -> Self:
        """Configure flag values for this field, for example for TCP flags"""
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


class SubStructureField(ConfigurableField[F, FrameT]):
    """Sub-frame field"""
    def __init__(self, sub_type: Type[FrameT]):
        super().__init__("sub")
        self.sub_type = sub_type
        self.sub_structure: FrameStructure[FrameT] = Structure.get_struct(sub_type)
        self.choice_resolver: Optional[Calculator] = None

    def get_choice(self, frame: F) -> FrameT:
        v = self.get(frame)
        if v.backend.choice:
            v = v.backend.choice.get(v)
        return v

    def choice_by(self, value: CalculatorSource) -> Self:
        """Configure the choice in field by given value"""
        selection = self.sub_structure
        if not isinstance(selection, Selection):
            raise ValueError(f"Structure {selection.structure_name} is not a selection, cannot use choice_by")
        choice_resolver = value.calculator()
        self.choice_resolver = choice_resolver

        def proc(f: Frame) -> None:
            choice = self.get(f)
            choice_struct = cast(Structure[Any], choice.backend.structure)
            key = selection.reverse_map.get(choice_struct, 0)  # value 0 assumed be the default choice key
            if key is None:
                raise ValueError(
                    f"Choice {choice_struct.structure_name} not found in selection {selection.structure_name}")
            choice_resolver.push(f.backend, key)

        self.structure.at_commit(proc)
        return self

    def select(self, frame: F, field: ConfigurableField[FrameT, Any]) -> FrameT:
        """Select sub-frame type for this frame"""
        sub = self.sub_type(frame.backend.factory())
        sub.backend.choice = field
        frame.backend.set(self, sub)
        return sub

    def process_frame(self, frame: F, procedures: Dict[Type[Frame] | AnyField, Callable[[Any], V]]) -> Optional[V]:
        """Process frame here differentiating by frame type or choice field"""
        # TODO: Refactor, now this takes the confusing procedure dict and method is not unit tested but used in Toolsaf
        v = self.get(frame)
        if v.structure.is_selection:
            # let's assume that the selection choices are the keys
            field = v.backend.choice
            if field:
                proc = procedures.get(field)
                if proc:
                    v = field.get(v)
        else:
            proc = procedures.get(type(v))
        return proc(v) if proc else None

    def get_default_value(self, frame: F) -> FrameT:
        return self.sub_type(frame.backend.factory())

    def encoding_bit_length(self, backend: FrameBackend, value: FrameT) -> int:
        return value.bit_length()

    def encode(self, value: FrameT, state: EncodingState) -> RawData:
        enc = value.encode()
        return enc

    def decode_bit_length(self, data: RawData, bit_offset: int, value: Optional[FrameT],
                          backend: 'FrameBackend') -> int:
        if value is not None:
            return value.bit_length()
        b_len = super().decode_bit_length(data, bit_offset, None, backend)
        if b_len >= 0:
            return b_len
        # if self.choice_resolver: ... not trying to resolve, as we would need to create the backend for it
        v = self.decode(data.tail_bits(bit_offset), -1, backend)
        return v.bit_length()

    def decode(self, data: RawData, bit_length: int, backend: FrameBackend) -> FrameT:
        sub_f = self.sub_type(backend.factory(decode=data))
        if self.choice_resolver:
            # make the choice
            key = self.choice_resolver.pull(backend)
            sub_field = sub_f.backend.structure.get_field_by(key)
            sub_f.backend.choice = sub_field
        return sub_f


class LengthOfLV(Calculator):
    """Get length of length-value field"""
    def __init__(self, field: 'LVField[Any, Any]'):
        super().__init__(None)
        self.field = field

    def pull(self, backend: 'FrameBackend') -> float:
        bit_off = backend.get_bit_offset(self.field.offset)
        data = backend.input_data().sub_block_bits(0, bit_off)
        v = self.field.length_codec.decode(data)
        return float(v)


class LVField(ConfigurableField[F, T]):
    """Field with length prefix"""
    def __init__(self, sub: Field[F, T], length: IntegerFormat = IntegerFormat()) -> None:
        super().__init__("LV")
        sub_field = cast(ConfigurableField[F, T], sub)
        self.sub = sub_field
        self.structure = sub_field.structure
        self.length_codec = length.create_codec()
        if self.length_codec.get_fixed_bit_length() < 0:
            raise StructureError("Variable-length length in LV not supported, yet")
        self.length_resolver = LengthOfLV(self)
        sub.consumed_by = self

    def get_default_value(self, frame: F) -> T:
        return self.sub.get_default_value(frame)

    def encoding_bit_length(self, backend: FrameBackend, value: T) -> int:
        len_len: int = self.length_codec.get_fixed_bit_length()
        v_len: int = self.sub.encoding_bit_length(backend, value)
        return len_len + v_len

    def encode(self, value: T, state: EncodingState) -> RawData:
        value_r: RawData = self.sub.encode(value, state)
        len_v = value_r.byte_length()  # NOTE: How to add calculations here (no backend)?
        len_r: RawData = self.length_codec.encode(len_v)
        return len_r + value_r

    def decode(self, data: RawData, bit_length: int, backend: FrameBackend) -> T:
        d_len = self.length_codec.decode(data) * 8
        d_data = data.sub_block_bits(self.length_codec.get_fixed_bit_length(), d_len)
        return self.sub.decode(d_data, -1, backend)

    def decode_bit_length(self, data: RawData, bit_offset: int, value: T | None, backend: 'FrameBackend') -> int:
        l_data = data.tail_bits(bit_offset)
        d_len: int = self.length_codec.decode(l_data) * 8
        len_len: int = self.length_codec.get_fixed_bit_length()
        return len_len + d_len


class FrameIterator(Iterator[FrameT]):
    """Frame iterator"""
    def __init__(self, source: Iterator[FrameT]):
        self.source = source

    def __next__(self) -> FrameT:
        return self.source.__next__()


class Sequence(ConfigurableField[F, List[FrameT]]):
    """Field of sequence of values"""
    def __init__(self, sub: Field[F, FrameT]):
        super().__init__("sequence", [])
        sub_field = cast(ConfigurableField[F, FrameT], sub)
        self.sub = sub
        self.structure = sub_field.structure
        self.item_frame: Optional[Type[FrameT]] = None
        if isinstance(sub, SubStructureField):
            self.item_frame = sub.sub_type
            self.item_fixed_bit_length = -1  # Note: Structure should support this!
        else:
            self.item_fixed_bit_length = self.sub.fixed_bit_length
        self.count_resolver: Optional[Calculator] = None
        self.terminator_call: Optional[Callable[[FrameT], bool]] = None
        sub.consumed_by = self

    def count_by(self, value: CalculatorSource) -> Self:
        """Set value to resolve count of items in this sequence"""
        self.count_resolver = value.calculator()
        return self

    def terminator_test(self, test: Callable[[Any], bool]) -> Self:
        """Set the test to resolve terminator for this sequennce"""
        self.terminator_call = test
        return self

    def iterate(self, frame: F) -> FrameIterator[FrameT]:
        """Get item by index"""
        known_count = int(self.count_resolver.pull(frame.backend)) if self.count_resolver else -1
        s = frame.backend.iterate(self, self.sub, known_count, self.terminator_call)
        return FrameIterator(s)

    def get_count(self, frame: F) -> int:
        """Get count of items in this sequence"""
        if self.count_resolver:
            return int(self.count_resolver.pull(frame.backend))
        # horrible way...
        c = 0
        it = self.iterate(frame)
        for _ in it:
            c += 1
        return c

    def item(self, frame: F, index: int) -> FrameT:
        """Get item by index"""
        item = frame.backend.get_item(self, self.sub, index)
        return item

    def set_repeat(self, frame: F, count: int) -> List[FrameT]:
        """Set value by repeating item given times"""
        v = []
        for _ in range(0, count):
            v.append(self.sub.get_default_value(frame))
        frame.backend.set(self, v)
        return v

    def get_default_value(self, frame: F) -> List[FrameT]:
        return []

    def encoding_bit_length(self, backend: FrameBackend, value: List[FrameT]) -> int:
        if self.sub.fixed_bit_length >= 0:
            return self.sub.fixed_bit_length * len(value)
        b_len = 0
        for v in value:
            b_len += self.sub.encoding_bit_length(backend, v)
        # Note: terminator must be in the list
        return b_len

    def encode(self, value: List[FrameT], state: EncodingState) -> RawData:
        r = []
        for v in value:
            r.append(self.sub.encode(v, state))
        # Note: terminator must be in the list
        return Raw.sequence(r)

    def decode_bit_length(self, data: RawData, bit_offset: int, value: Optional[List[FrameT]],
                          backend: 'FrameBackend') -> int:
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
            b_data = data.tail_bits(bit_offset + b_off)
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

    def decode(self, data: RawData, bit_length: int, backend: FrameBackend) -> List[FrameT]:
        known_count = int(self.count_resolver.pull(backend)) if self.count_resolver else -1
        items: List[FrameT] = []
        previous = None
        while True:
            if 0 <= known_count <= len(items):
                break
            if previous is not None:
                v_len = self.sub.decode_bit_length(data, 0, previous, backend)
                data = data.tail_bits(v_len)
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

    def _update_fixed_length(self, field: AnyField) -> None:
        """Update fixed length or reset it to -1"""
        if self.fields_fixed_bit_offset < 0 or field.fixed_bit_length < 0:
            self.fields_fixed_bit_offset = -1
        else:
            self.fields_fixed_bit_offset += field.fixed_bit_length

    def field(self, field: AnyField, name: str = "") -> AnyField:
        assert isinstance(field, ConfigurableField), "I thought all fields are configurable"
        fn = self._get_a_name(name)
        field.structure = self
        self.fields[fn] = field
        self._update_fixed_length(field)
        return field

    def raw(self, bits: int = -1, bytes: int = -1,  # pylint: disable=redefined-builtin
            min_bits: int = -1, min_bytes: int = -1,
            default: RawData | None = None, name: str = "") -> RawField[F]:
        """Add raw data field"""
        fn = self._get_a_name(name)
        fix_len = -1
        if bits >= 0:
            fix_len = bits
        if bytes >= 0:
            fix_len = bytes * 8
        min_len = fix_len
        if min_bits >= 0:
            min_len = min_bits
        if min_bytes >= 0:
            min_len = min_bytes * 8
        assert min_len <= fix_len, f"Minimun length is {min_len} bits and max length is {fix_len} bits"
        if default is None:
            default = Raw.empty if min_len < 0 else Raw.zeroes(bit_length=min_len)
        f: RawField[F] = RawField(default, min_len, fix_len, self.fields_fixed_bit_offset)
        f.structure = self
        self.fields[fn] = f
        self._update_fixed_length(f)
        return f

    def integer(self, int_format: IntegerFormat = IntegerFormat(),
                bytes: int =-1, bits: int =-1,  # pylint: disable=redefined-builtin
                default: int = 0, name: str = "") -> IntField[F]:
        """Add integer field"""
        fn = self._get_a_name(name)
        if bytes > 0:
            int_format = int_format.bytes(bytes)
        if bits > 0:
            int_format = int_format.bits(bits)
        codec = int_format.create_codec()
        f: IntField[F] = IntField(codec, default, fixed_bit_offset=self.fields_fixed_bit_offset)
        f.structure = self
        self.fields[fn] = f
        self._update_fixed_length(f)
        return f

    def sub(self, sub_frame: Type[FrameT], name: str = "") -> SubStructureField[F, FrameT]:
        """Add sub-frame field"""
        fn = self._get_a_name(name)
        f: SubStructureField[F, FrameT] = SubStructureField(sub_frame)
        f.structure = self
        self.fields[fn] = f
        self._update_fixed_length(f)
        return f

    def at_commit(self, update: Callable[[F], None]) -> Self:
        """Set update procedure to call on commit"""
        self.commit_procedures.append((None, update))
        return self


class Selection(Structure[F]):
    """A frame which only the chosen field is present"""
    def __init__(self) -> None:
        super().__init__()
        self.is_selection = True
        self.choice_map: Dict[Any, AnyField] = {}
        self.reverse_map: Dict[Structure[Any], Any] = {}

    def _update_fixed_length(self, field: AnyField) -> None:
        self.fields_fixed_bit_offset = 0  # all choices start from offset 0

    def choice(self, key: Any, value: ConfigurableField[F, T]) -> ConfigurableField[F, T]:
        """Add choice to this selection by providing key value and the choice field"""
        if key in self.choice_map:
            raise StructureError(f"Duplicate key {key} in {self.structure_name}")
        assert isinstance(value, ConfigurableField), "Provide a field for choice(...)"
        self.choice_map[key] = value
        self.reverse_map[value.structure] = key
        return value

    def get_field_by(self, key: Any = None) -> Field[F, Any]:
        if key is not None:
            f = self.choice_map.get(key)
            if f:
                return f
        return super().get_field_by(key)

    def _resolve_offsets(self) -> None:
        pass  # all zeroes ok
