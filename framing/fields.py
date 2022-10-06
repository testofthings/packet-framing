import enum
from typing import Iterator

from framing.base import *


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
        value = self.next_step.pull(backend)
        len_v = max(0, self.target_length - int(value))
        return len_v


class ValueOf:
    """Get value from the given field"""
    def __init__(self, field: 'IntField'):
        self.end: Calculator = field

    def __mul__(self, value: float) -> 'ValueOf':
        self.end = Multiplier(value, self.end)
        return self

    def __truediv__(self, value: float) -> 'ValueOf':
        self.end = Multiplier(1 / value, self.end)
        return self

    def copy_to(self, field: 'IntField') -> Self:
        self.end = CopyToField(field, self.end)
        return self


class ConfigurableField(Field[F, T]):

    def length_by(self, value: ValueOf) -> Self:
        self.length_resolver = Multiplier(8, value.end)
        field = self

        def procedure(frame: F):
            f_len = field.get_bit_length(frame)
            field.length_resolver.push(frame.backend, f_len)
        # call at commit to push length
        self.structure.commit_procedures.append((self, procedure))
        return self

    def terminator(self, value: RawData) -> Self:
        self.end_offset_resolver = FieldLengthByTerminator(self, value)
        return self

    def end_offset_by(self, value: ValueOf) -> Self:
        calc = Multiplier(8, value.end)
        self.end_offset_resolver = calc
        field = self

        def procedure(frame: F):
            f_off = frame.backend.get_bit_offset(field.offset)
            f_len = field.get_bit_length(frame)
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
    def __init__(self, default_value: RawData):
        super().__init__("raw", default_value)

    def fixed_length(self, bit_length: int):
        self.fixed_bit_length = bit_length

    def get(self, frame: F) -> RawData:
        v = frame.backend.get(self)
        if isinstance(v, Frame):
            # payload can be a frame
            return v.encode()
        return v

    def __getitem__(self, frame: F) -> T:
        v = frame.backend.get(self)
        if isinstance(v, Frame):
            # payload can be a frame
            return v.encode()
        return v

    def get_bit_length(self, frame: F, value: Optional[RawData] = None) -> int:
        if value is not None:
            return value.bit_length()
        b_len = frame.backend.resolve_bit_length(self)
        if b_len < 0:
            # must resolve value to know the length
            v = self.get(frame)
            b_len = v.bit_length()
        return b_len

    def encode(self, value: RawData, state: EncodingState) -> RawData:
        return value

    def decode(self, data: RawData, backend: FrameBackend) -> RawData:
        if self.fixed_bit_length < 0:
            return data  # read it all
        return data.subBlockBits(0, self.fixed_bit_length)


class IntField(ConfigurableField[F, int], Calculator):
    """Integer field"""
    def __init__(self, codec: IntegerCodec, default_value: int):
        super().__init__("int", default_value)
        self.codec = codec
        self.fixed_bit_length = codec.get_fixed_bit_length()

    def flag_values(self, definition: Type[enum.IntFlag]) -> Self:
        return self

    def get_bit_length(self, frame: F, value: Optional[int] = None) -> int:
        b_len = self.codec.get_fixed_bit_length()
        if b_len < 0:
            b_len = frame.backend.resolve_bit_length(self)
        if b_len < 0:
            v = self.get(frame) if value is None else value
            b_len = self.codec.get_bit_length(v)
        return b_len

    def get_byte_length(self, frame: F, value: Optional[int] = None) -> int:
        if self.fixed_bit_length >= 0:
            return self.fixed_bit_length // 8
        return self.codec.get_bit_length(self.get(frame)) // 8

    def encode(self, value: int, state: EncodingState) -> RawData:
        return self.codec.encode(value)

    def decode(self, data: RawData, backend: FrameBackend) -> int:
        return self.codec.decode(data)

    def pull(self, backend: FrameBackend) -> float:
        return backend.get(self)

    def push(self, backend: FrameBackend, value: float) -> float:
        return backend.set(self, int(value))


FT = typing.TypeVar("FT", bound=Frame)


class SubStructureField(ConfigurableField[F, FT]):
    """Sub-frame field"""
    def __init__(self, sub_type: Type[FT]):
        super().__init__("sub", None)
        self.sub_type = sub_type
        self.sub_structure = Structure.get_struct(sub_type)

    def get_default_value(self, frame: F) -> FT:
        return self.sub_type(frame.backend.factory())

    def get_bit_length(self, frame: F, value: Optional[FT] = None) -> int:
        if value is not None:
            return value.get_bit_length()
        b_len = frame.backend.resolve_bit_length(self)
        if b_len < 0:
            # must resolve value
            value = frame.backend.get(self)
            b_len = value.get_bit_length()
        return b_len

    def encode(self, value: FT, state: EncodingState) -> RawData:
        enc = value.encode()
        return enc

    def decode(self, data: RawData, backend: FrameBackend) -> FT:
        return self.sub_type(backend.factory(decode=data))


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

    def get_bit_length(self, frame: F, value: Optional[T] = None) -> int:
        len_len = self.length_codec.get_fixed_bit_length()
        value_len = self.sub.get_bit_length(frame, value)
        return len_len + value_len

    def encode(self, value: T, state: EncodingState) -> RawData:
        value_r = self.sub.encode(value, state)
        len_v = value_r.byte_length()  # NOTE: How to add calculations here (no backend)?
        len_r = self.length_codec.encode(len_v)
        return len_r + value_r

    def decode(self, data: RawData, backend: FrameBackend) -> T:
        len_len = self.length_codec.decode(data) * 8
        d_data = data.subBlockBits(self.length_codec.get_fixed_bit_length(), len_len)
        return self.sub.decode(d_data, backend)

    def pull(self, backend: FrameBackend) -> float:
        return backend.get(self.sub)

    def push(self, backend: FrameBackend, value: float):
        backend.set(self.sub, value)


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
        self.terminator_value: Optional[FT] = None
        sub.consumed_by = self

    def count_by(self, value: ValueOf) -> Self:
        self.count_resolver = value.end
        return self

    def terminate_by(self, value) -> Self:
        self.terminator_value = value
        return self

    def iterate(self, frame: F) -> Iterator[FT]:
        """Get item by index"""
        known_count = int(self.count_resolver.pull(frame.backend)) if self.count_resolver else -1
        return frame.backend.iterate(self, self.sub, known_count, self.terminator_value)

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

    def get_bit_length(self, frame: F, value: Optional[List[FT]] = None) -> int:
        if value is not None:
            if self.item_fixed_bit_length >= 0:
                return self.item_fixed_bit_length * len(value)
        b_len = frame.backend.resolve_bit_length(self)
        if b_len >= 0:
            return b_len
        # must resolve value
        value = frame.backend.get(self)
        b_len = 0
        for v in value:
            b_len += self.sub.get_bit_length(v)
        return b_len

    def encode(self, value: List[FT], state: EncodingState) -> RawData:
        r = []
        for v in value:
            r.append(self.sub.encode(v, state))
        if self.terminator_value:
            r.append(self.sub.encode(self.terminator_value, state))
        return Raw.sequence(r)

    def decode(self, data: RawData, backend: FrameBackend) -> List[FT]:
        known_count = int(self.count_resolver.pull(backend)) if self.count_resolver else -1
        r = []
        while True:
            if 0 <= known_count <= len(r):
                break
            if data.octet(0) < 0:
                break  # no more data to read
            v = self.sub.decode(data, backend)
            if v == self.terminator_value:
                break
            v_len = self.sub.get_bit_length(backend, v)
            r.append(v)
            data = data.tailBits(v_len)
        return r


class Structure(FrameStructure[F]):
    """Frame structure definition"""

    def raw(self, bits: int = None, bytes: int = None, default: RawData = Raw.empty,
            name: str = None) -> RawField[F]:
        fn = self._get_a_name(name)
        default = default if default else Raw.zeroes(bit_length=bits, byte_length=bytes)
        f: RawField[F] = RawField(default)
        f.structure = self
        if bits is not None:
            f.fixed_length(bits)
        if bytes is not None:
            f.fixed_length(bytes * 8)
        self.fields[fn] = f
        return f

    def integer(self, int_format: IntegerFormat, default=0, name: str = None) -> IntField[F]:
        fn = self._get_a_name(name)
        codec = int_format.create_codec()
        f = IntField(codec, default)
        f.structure = self
        self.fields[fn] = f
        return f

    def sub(self, sub_frame: Type[FT], name: str = None) -> SubStructureField[F, FT]:
        fn = self._get_a_name(name)
        f = SubStructureField(sub_frame)
        f.structure = self
        self.fields[fn] = f
        return f

    def at_commit(self, update: Callable[[F], None]):
        self.commit_procedures.append((None, update))
