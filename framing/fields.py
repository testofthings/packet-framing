from framing.base import *


class RawField(FieldBase[F, RawData]):
    """Raw data field"""
    def __init__(self, default_value: RawData):
        super().__init__("raw", default_value)

    def fixed_length(self, bit_length: int):
        self.fixed_bit_length = bit_length

    def get_bit_length(self, frame: F, value: Optional[RawData] = None) -> int:
        if self.fixed_bit_length >= 0:
            return self.fixed_bit_length
        if value is not None:
            return value.bit_length()
        # do not know my length without encoding/decoding it
        v: RawData = frame.backend.get(self)
        return v.bit_length()

    def encode(self, value: RawData, state: EncodingState) -> RawData:
        return value

    def decode(self, data: RawData, backend: FrameBackend) -> RawData:
        if self.fixed_bit_length < 0:
            return data  # read it all
        return data.subBlockBits(0, self.fixed_bit_length)


class IntField(FieldBase[F, int], Calculator):
    """Integer field"""
    def __init__(self, codec: IntegerCodec, default_value: int):
        super().__init__("int", default_value)
        self.codec = codec
        self.fixed_bit_length = codec.get_fixed_bit_length()

    def get_bit_length(self, frame: F, value: Optional[int] = None) -> int:
        if self.fixed_bit_length >= 0:
            return self.fixed_bit_length
        return self.codec.get_bit_length(self.get(frame))

    def get_byte_length(self, frame: F, value: Optional[int] = None) -> int:
        if self.fixed_bit_length >= 0:
            return self.fixed_bit_length // 8
        return self.codec.get_bit_length(self.get(frame)) // 8

    def encode(self, value: int, state: EncodingState) -> RawData:
        return self.codec.encode(value)

    def decode(self, data: RawData, backend: FrameBackend) -> int:
        return self.codec.decode(data)

    def pull(self, backend: FrameBackend) -> int:
        return backend.get(self)

    def push(self, backend: FrameBackend, value: int):
        backend.set(self, value)


class StringField(FieldBase[F, str]):
    """String field"""
    def __init__(self, default_value: str):
        super().__init__("str", default_value)

    def encode(self, value: str, state: EncodingState) -> RawData:
        return Raw.empty  # FIXME


FT = typing.TypeVar("FT", bound=Frame)


class SubStructureField(FieldBase[F, FT]):
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
        # must resolve value
        value = frame.backend.get(self)
        return value.get_bit_length()

    def encode(self, value: FT, state: EncodingState) -> RawData:
        enc = value.encode()
        return enc

    def decode(self, data: RawData, backend: FrameBackend) -> FT:
        return self.sub_type(backend.factory(decode=data))


class Sequence(FieldBase[F, List[FT]]):
    def __init__(self, sub: FieldBase[F, FT]):
        super().__init__("sequence", [])
        self.sub = sub
        if isinstance(sub, SubStructureField):
            self.item_type = sub.sub_type
            self.item_codec = None
            self.item_fixed_bit_length = -1  # Note: Structure should support this!
        else:
            raise NotImplementedError("Only sub-structure sequences supported, now")
            # self.item_fixed_bit_length = self.item_codec.get_fixed_bit_length() if item_codec else -1
        sub.consumed_by = self

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
        else:
            # must resolve value
            value = frame.backend.get(self)
        bit_l = 0
        for v in value:
            if isinstance(v, Frame):
                bit_l += v.get_bit_length()
            else:
                bit_l += self.item_codec.get_bit_length(v)
        return bit_l

    def encode(self, value: List[FT], state: EncodingState) -> RawData:
        r = []
        for v in value:
            if isinstance(v, Frame):
                r.append(v.encode())
            else:
                r.append(self.item_codec.encode(v))
        return Raw.merge(r)

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
        self.fields[fn] = f
        return f

    def string(self, name: str = None, default="") -> StringField[F]:
        fn = self._get_a_name(name)
        f = StringField(default)
        self.fields[fn] = f
        return f

    def sub(self, sub_frame: Type[FT], name: str = None) -> SubStructureField[F, FT]:
        fn = self._get_a_name(name)
        f = SubStructureField(sub_frame)
        self.fields[fn] = f
        return f

    def at_commit(self, update: Callable[[F], None]):
        self.commit_procedures.append(update)
