import math
from typing import Iterator

from framing.base import *


class Multiplier(Calculator):
    """Multiply (or divide) the value"""
    def __init__(self, multiplier: float, next_step: Calculator):
        super().__init__(next_step)
        self.multiplier = multiplier

    def pull(self, backend: 'FrameBackend') -> float:
        return self.next_step.pull(backend) * self.multiplier

    def push(self, backend: 'FrameBackend', value: float):
        self.next_step.push(backend, value / self.multiplier)


class CopyToField(Calculator):
    """Copy value to other field on push"""
    def __init__(self, field: 'IntField', next_step: Calculator):
        super().__init__(next_step)
        self.field = field

    def push(self, backend: 'FrameBackend', value: float):
        backend.set(self.field, int(value))
        self.next_step.push(backend, value)


class AddFieldOffset(Calculator):
    """Add field offset to value on push, subtract on pull"""
    def __init__(self, field: Field, next_step: Calculator):
        super().__init__(next_step)
        self.field = field

    def push(self, backend: 'FrameBackend', value: float):
        off = backend.get_bit_offset(self.field.offset)
        self.next_step.push(backend, value + off)

    def pull(self, backend: 'FrameBackend') -> float:
        off = backend.get_bit_offset(self.field.offset)
        return self.next_step.pull(backend) - off


class FieldOffsetValue(Calculator):
    """Get field offset value"""
    def __init__(self, field: Field):
        super().__init__(None)
        self.field = field

    def pull(self, backend: 'FrameBackend') -> float:
        return backend.get_bit_offset(self.field.offset)


class PaddingValue(Calculator):
    """Get padding value, next step calculates padded length"""
    def __init__(self, target_length: int, next_step: Calculator):
        super().__init__(next_step)
        self.target_length = target_length * 8  # target_length in bytes

    def pull(self, backend: 'FrameBackend') -> float:
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

    def end_offset_by(self, value: ValueOf) -> Self:
        calc = Multiplier(8, value.end)
        calc = AddFieldOffset(self, calc)
        self.length_resolver = calc
        field = self

        def procedure(frame: F):
            f_len = field.get_bit_length(frame)
            field.length_resolver.push(frame.backend, f_len)
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

    def push(self, backend: FrameBackend, value: float):
        backend.set(self, int(value))


FT = typing.TypeVar("FT", bound=Frame)


class SubStructureField(ConfigurableField[F, FT]):
    """String field"""
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


class Sequence(ConfigurableField[F, List[FT]]):
    def __init__(self, sub: Field[F, FT]):
        super().__init__("sequence", [])
        self.sub = sub
        self.structure = sub.structure
        if isinstance(sub, SubStructureField):
            self.item_type = sub.sub_type
            self.item_codec = None
            self.item_fixed_bit_length = -1  # Note: Structure should support this!
        else:
            raise NotImplementedError("Only sub-structure sequences supported, now")
            # self.item_fixed_bit_length = self.item_codec.get_fixed_bit_length() if item_codec else -1
        sub.consumed_by = self

    def iterate(self, frame: F) -> Iterator[FT]:
        """Get item by index"""
        return frame.backend.iterate(self, self.sub)

    def get_item(self, frame: F, index: int) -> FT:
        return frame.backend.get_item(self, self.sub, index)

    def set_repeat(self, frame: F, count: int) -> List[F]:
        """Set value by repeating item given times"""
        v = []
        if self.item_codec:
            v = [self.item_codec.default_value()] * count
        else:
            factory = frame.backend.factory()
            for _ in range(0, count):
                v.append(self.item_type(factory))
        self.set(frame, v)
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
            if isinstance(v, Frame):
                b_len += v.get_bit_length()
            else:
                b_len += self.item_codec.get_bit_length(v)
        return b_len

    def encode(self, value: List[FT], state: EncodingState) -> RawData:
        r = []
        for v in value:
            if isinstance(v, Frame):
                r.append(v.encode())
            else:
                r.append(self.item_codec.encode(v))
        return Raw.sequence(r)

    def decode(self, data: RawData, backend: FrameBackend) -> List[FT]:
        r = []
        while True:
            if data.octet(0) < 0:
                break  # no more data to read
            if self.item_codec:
                v = self.item_codec.decode(data)
                v_len = self.item_codec.get_bit_length(v)
            else:
                v = self.item_type(backend.factory(data))
                v_len = v.get_bit_length()
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
