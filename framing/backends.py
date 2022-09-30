import copy
from typing import Dict, Any, Callable, Iterator, Optional, List

from typing_extensions import Self

from framing.base import FrameBackend, Frame, EncodingState, FieldBase, F, T, LayerMapping, FieldOffset
from framing.fields import Sequence, FT, Structure
from framing.raw_data import RawData, Raw


class BackendImplementation(FrameBackend):
    def __init__(self, frame: Frame):
        super().__init__(frame)
        self.mappings: List[LayerMapping] = []
        self.known_bit_length = -1

    def get_bit_length(self) -> int:
        if self.known_bit_length < 0:
            self.known_bit_length = self.get_bit_offset(self.structure.fields_length)
        return self.known_bit_length

    def add_mapping(self, mapping: 'LayerMapping') -> Self:
        self.mappings.append(mapping)
        return self

    def dump(self, bit_offset=0, indent='', width=80, copy_to_avoid_update=False) -> str:
        if copy_to_avoid_update:
            return self.copy(commit=True).dump(bit_offset, indent, width, copy_to_avoid_update=False)
        r = []

        def prefix(offset: int, name: str, data="") -> str:
            s = f"{offset // 8:06x} {indent} "
            s_len = max(0, width - 8 - len(indent) - len(name) - len(data))
            return s + name + " " * s_len + f"{data}"

        state = EncodingState()
        bit_off = bit_offset
        for n, f in self.structure.fields.items():
            i_off = bit_off
            v = self.get_as_frame(f)
            if isinstance(v, RawFrame):
                v = self.get(f)
            if isinstance(f, Sequence):
                for num, i in enumerate(v):
                    r.append(prefix(i_off, "{num}/{len(v)}"))
                    v_s = i.backend.dump(bit_offset=bit_off, indent=indent + '  ', width=width)
                    r.append(v_s)
                continue
            if isinstance(v, Frame):
                r.append(prefix(i_off, n))
                v_s = v.backend.dump(bit_offset=bit_off, indent=indent + '  ', width=width)
                r.append(v_s)
                continue
            ev = f.encode(v, state)
            sv = ev.dump(always_wide=True).split("\n")
            for i in range(0, len(sv)):
                if i == 0:
                    line = prefix(i_off, n, sv[i])
                else:
                    line = prefix(i_off, "", sv[i])
                r.append(line)
                i_off += 16 * 8
            bit_off += f.get_bit_length(self.frame, value=v)
        return "\n".join(r)

    def copy(self, commit=False) -> Self:
        raise NotImplementedError()

    def __repr__(self):
        # create a copy to show, so that we do not update state
        return self.dump(copy_to_avoid_update=True)


class RawFrame(Frame):
    structure = Structure['RawFrame']()
    data = structure.raw()


class ComposingBackend(BackendImplementation):
    """Backend to compose a frame"""
    def __init__(self, frame: Frame):
        super().__init__(frame)
        self.changes: Dict[FieldBase, Any] = {}

    def get(self, field: FieldBase[F, T]) -> T:
        v = self.changes.get(field)
        if v is None:
            v = field.get_default_value(self.frame)
            self.changes[field] = v
        return v

    def set(self, field: FieldBase[F, T], value: T) -> Self:
        self.changes[field] = value
        return self

    def get_item(self, sequence_field: FieldBase, item_field: FieldBase[F, FT], index: int):
        val = self.get(sequence_field)
        return val[index]

    def get_as_frame(self, field: FieldBase[F, T]) -> Frame:
        # FIXME: Not implemented
        return RawFrame(self.factory())

    def factory(self, decode: RawData = None) -> Callable[[Frame], FrameBackend]:
        def f(frame: Frame):
            b = ComposingBackend(frame)
            b.mappings = self.mappings
            b.parent = self
            return b
        return f

    def get_bit_offset(self, offset: FieldOffset) -> int:
        off = offset.fixed_bit_offset
        prefix = offset.prefix
        if prefix:
            # resolve prefix dynamic length
            off += self.get_bit_offset(prefix)
            if prefix.variable_field:
                off += prefix.variable_field.get_bit_length(self.frame)
        return off

    def resolve_bit_length(self, field: FieldBase[F, T]) -> int:
        b_len = -1
        if field.fixed_bit_length >= 0:
            # Fixed-length field
            b_len = field.fixed_bit_length
        # NOTE: We do *not* call length resolvers, they are called in commit to update fields
        return b_len

    def encode(self) -> RawData:
        self.structure.commit(self.frame)
        self.known_bit_length = -1
        f_list = []
        state = EncodingState()
        for f in self.structure.fields.values():
            v = self.get(f)
            f_list.append(f.encode(v, state))
        return Raw.sequence(f_list)

    def copy(self, commit=False) -> Self:
        n_frame = copy.copy(self.frame)
        c = ComposingBackend(n_frame)
        n_frame.backend = c
        c.changes.update(self.changes)
        if commit:
            c.encode()
        return c


class DissectorBackend(BackendImplementation):
    """Backend to dissect frame from raw data"""
    def __init__(self, frame: Frame, data: RawData):
        super().__init__(frame)
        self.is_decoding = True
        self.data = data
        self.post_offset: Dict[FieldBase, int] = {}  # NOTE: Post offsets for variable-length fields
        self.value_cache: Dict[FieldBase, Any] = {}

    def get(self, field: FieldBase[F, T]) -> T:
        v = self.value_cache.get(field)
        if v is None:
            bit_offset = self.get_bit_offset(field.offset)
            data = self.data.tailBits(bit_offset)
            # FIXME: Nuke length procedure?
            if field.decode_length_procedure:
                f_len = field.decode_length_procedure(self.frame)
                data = data.subBlockBits(0, f_len)
            if field.fixed_bit_length < 0 and field.offset.min_tail_length:
                data_len = data.bit_length()
                if data_len >= field.offset.min_tail_length:
                    # limit data length to leave space for the tail
                    data = data.subBlockBits(0, data_len - field.offset.min_tail_length)
            if field.length_resolver:
                f_len = field.length_resolver.pull(self)
                data = data.subBlockBits(0, f_len)
            v = field.decode(data, self)
            self.value_cache[field] = v
        return v

    def set(self, field: FieldBase[F, T], value: T) -> Self:
        raise NotImplementedError("set() not supported")

    def get_item(self, sequence_field: FieldBase, item_field: FieldBase[F, FT], index: int):
        v = self.value_cache.get(sequence_field)
        if v is not None:
            return v[index]

        bit_offset = self.get_bit_offset(sequence_field.offset)
        data = self.data.tailBits(bit_offset)
        i = 0
        while True:
            v = item_field.decode(data, self)
            if i == index:
                return v
            v_len = v.get_bit_length()
            data = data.tailBits(v_len)
            bit_offset += v_len
            i += 1

    def get_bit_offset(self, offset: FieldOffset) -> int:
        off = offset.fixed_bit_offset
        prefix = offset.prefix
        if prefix:
            # resolve prefix dynamic length
            off += self.get_bit_offset(prefix)
            if prefix.variable_field:
                cached = self.post_offset.get(prefix.variable_field)
                if cached is not None:
                    return cached
                if prefix.variable_field.decode_length_procedure:
                    f_len = prefix.variable_field.decode_length_procedure(self.frame)
                    off += f_len
                else:
                    # NOTE: We could check if value is cached and provide it
                    off += prefix.variable_field.get_bit_length(self.frame)
                self.post_offset[prefix.variable_field] = off
        return off

    def resolve_bit_length(self, field: FieldBase[F, T]) -> int:
        b_len = -1
        if field.fixed_bit_length >= 0:
            # Fixed-length field
            b_len = field.fixed_bit_length
        elif field.decode_length_procedure:
            # Length procedure (FIXME: Nuke these?)
            b_len = field.decode_length_procedure(self.frame)
        elif field.length_resolver:
            # Length resolver
            b_len = field.length_resolver.pull(self)
        if b_len == -1 and field.offset.min_tail_length > 0:
            # limit data length to leave space for the tail
            off = self.get_bit_offset(field.offset)
            tail_len = self.data.bit_length() - off
            b_len = max(tail_len - field.offset.min_tail_length, 0)
        return b_len

    def factory(self, decode: RawData = None) -> Callable[[Frame], FrameBackend]:
        def f(frame: Frame):
            if decode is None:
                b = ComposingBackend(frame)
            else:
                b = DissectorBackend(frame, decode)
            b.mappings = self.mappings
            b.parent = self
            return b
        return f

    def iterate(self, sequence_field: FieldBase, item_field: FieldBase[F, FT]) -> Iterator[FT]:
        v = self.value_cache.get(sequence_field)
        if v is not None:
            return v.__iter__()  # already value in memory (we do not store it here)

        backend = self
        data = self.data

        class ItemIterator(Iterator[FT]):
            def __init__(self, offset: int):
                self.offset = offset

            def __next__(self) -> Optional[FT]:
                n_data = data.tailBits(self.offset)
                if n_data.octet(0) < 0:
                    raise StopIteration()
                v = item_field.decode(n_data, backend)
                self.offset += v.get_bit_length()
                return v

        off = self.get_bit_offset(sequence_field.offset)
        return ItemIterator(off)

    def get_as_frame(self, field: FieldBase[F, T]) -> Frame:
        bit_offset = self.get_bit_offset(field.offset)
        bit_len = self.resolve_bit_length(field)
        if bit_len >= 0:
            data = self.data.subBlockBits(bit_offset, bit_len)
        else:
            data = self.data.tailBits(bit_offset)
        for m in self.mappings:
            for f_ptr, mm in m.get_mappings(field).items():
                value = f_ptr.get(self.frame)
                if value is None or value not in mm:
                    continue
                f_type = mm[value]
                return f_type(self.factory(data))
        # No explicit frame type found...
        return RawFrame(self.factory(data))

    def encode(self) -> RawData:
        bit_length = self.frame.get_bit_length()
        return self.data.tailBits(bit_length)

    def input_data(self) -> RawData:
        return self.data

    def copy(self, commit=False) -> Self:
        # do not read more data for printing
        limited_data = self.data.subBlockBits(0, self.data.bits_available())

        n_frame = copy.copy(self.frame)
        c = DissectorBackend(n_frame, limited_data)
        n_frame.backend = c
        c.value_cache.update(self.value_cache)
        return c
