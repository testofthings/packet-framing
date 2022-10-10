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
            v = frame.backend.get(field)
            f_len = field.encoding_bit_length(frame.backend, v)
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

    def __getitem__(self, frame: F) -> RawData:
        return self.get(frame)

    def get_bit_length(self, frame: F) -> int:
        """Get bit length for a value"""
        v = frame.backend.get(self)
        return v.bit_length() if isinstance(v, Frame) else v.bit_length()

    def encoding_bit_length(self, backend: FrameBackend, value: RawData) -> int:
        return value.bit_length()

    def encode(self, value: RawData, state: EncodingState) -> RawData:
        return value

    # NOTE: We never store the raw here, even as we could, as it can be mapped to frames...
    #def decode_bit_length(self, data: RawData, bit_offset: int, backend: 'FrameBackend') -> int:

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

    def encoding_bit_length(self, backend: FrameBackend, value: int) -> int:
        return self.codec.get_bit_length(value)

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

    def encoding_bit_length(self, backend: FrameBackend, value: FT) -> int:
        return value.bit_length()

    def encode(self, value: FT, state: EncodingState) -> RawData:
        enc = value.encode()
        return enc

    def decode_bit_length(self, data: RawData, bit_offset: int, backend: 'FrameBackend') -> int:
        b_len = super().decode_bit_length(data, bit_offset, backend)
        if b_len >= 0:
            return b_len
        v = self.decode(data.tailBits(bit_offset), backend)
        return v.bit_length()

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

    def encoding_bit_length(self, backend: FrameBackend, value: T) -> int:
        len_len = self.length_codec.get_fixed_bit_length()
        v_len = self.sub.encoding_bit_length(backend, value)
        return len_len + v_len

    def encode(self, value: T, state: EncodingState) -> RawData:
        value_r = self.sub.encode(value, state)
        len_v = value_r.byte_length()  # NOTE: How to add calculations here (no backend)?
        len_r = self.length_codec.encode(len_v)
        return len_r + value_r

    def decode(self, data: RawData, backend: FrameBackend) -> T:
        d_len = self.length_codec.decode(data) * 8
        d_data = data.subBlockBits(self.length_codec.get_fixed_bit_length(), d_len)
        return self.sub.decode(d_data, backend)

    def decode_bit_length(self, data: RawData, bit_offset: int, backend: 'FrameBackend') -> int:
        l_data = data.tailBits(bit_offset)
        d_len = self.length_codec.decode(l_data) * 8
        return self.length_codec.get_fixed_bit_length() + d_len

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

    def encoding_bit_length(self, backend: FrameBackend, value: List[FT]) -> int:
        if self.sub.fixed_bit_length >= 0:
            return self.sub.fixed_bit_length * len(value)
        b_len = 0
        for v in value:
            b_len += self.sub.encoding_bit_length(backend, v)
        if self.terminator_value is not None:
            b_len += self.sub.encoding_bit_length(backend, self.terminator_value)
        return b_len

    def encode(self, value: List[FT], state: EncodingState) -> RawData:
        r = []
        for v in value:
            r.append(self.sub.encode(v, state))
        if self.terminator_value:
            r.append(self.sub.encode(self.terminator_value, state))
        return Raw.sequence(r)

    def decode_bit_length(self, data: RawData, bit_offset: int, backend: 'FrameBackend') -> int:
        known_count = int(self.count_resolver.pull(backend)) if self.count_resolver else -1
        if known_count == 0 or (known_count >= 0 and self.fixed_bit_length >= 0):
            return known_count * self.sub.fixed_bit_length

        b_len = super().decode_bit_length(data, bit_offset, backend)
        if b_len >= 0:
            return b_len

        if known_count < 0 and self.terminator_value is None:
            return -1  # we decode everything...

        # The hard way...
        item_count = 0
        b_off = 0
        while True:
            if 0 <= known_count <= item_count:
                break
            b_data = data.tailBits(bit_offset + b_off)
            if b_data.octet(0) < 0:
                break  # no more data to read
            v_len = self.sub.decode_bit_length(b_data, 0, backend)
            assert v_len >= 0, "Sequence sub-value must know its length"
            b_off += v_len
            if self.terminator_value is not None:
                v = self.sub.decode(b_data, backend)
                if v == self.terminator_value:
                    break
            item_count += 1
        return b_off

    def decode(self, data: RawData, backend: FrameBackend) -> List[FT]:
        known_count = int(self.count_resolver.pull(backend)) if self.count_resolver else -1
        items = []
        previous = None
        while True:
            if 0 <= known_count <= len(items):
                break
            if previous is not None:
                v_len = self.sub.decode_bit_length(data, 0, backend)
                data = data.tailBits(v_len)
            if data.octet(0) < 0:
                break  # no more data to read
            v = self.sub.decode(data, backend)
            if v == self.terminator_value:
                break
            items.append(v)
            previous = v
        return items


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
