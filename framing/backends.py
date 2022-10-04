import copy
from typing import Dict, Any, Callable, Iterator, Optional, List, cast

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

    def dump(self, bit_offset=0, indent='', width=80, copy_sub_frames=False) -> str:
        def format_line(offset: int, name: str, data="") -> str:
            s = f"{offset // 8:06x} {indent} "
            s_len = max(0, width - 8 - len(indent) - len(name) - len(data))
            return s + name + " " * s_len + f"{data}"

        r = []
        state = EncodingState()
        bit_off = bit_offset
        for n, f in self.structure.fields.items():
            i_off = bit_off
            v = self.get(f)
            if isinstance(f, Sequence):
                for num, i in enumerate(v):
                    be = i.backend
                    if copy_sub_frames:
                        be = be.copy(parent=self)
                    r.append(format_line(i_off, f"{num + 1}/{len(v)}"))
                    v_s = be.dump(bit_offset=bit_off, indent=indent + '  ', width=width,
                                  copy_sub_frames=copy_sub_frames)
                    r.append(v_s)
                continue
            if isinstance(v, Frame):
                be = v.backend
                if copy_sub_frames:
                    be = be.copy(parent=self)
                r.append(format_line(i_off, f"{n} ({be.structure.structure_name})"))
                v_s = be.dump(bit_offset=bit_off, indent=indent + '  ', width=width, copy_sub_frames=copy_sub_frames)
                r.append(v_s)
                continue
            ev = f.encode(v, state)
            if ev.bit_length() == 0:
                r.append(format_line(i_off, n, "()" + " " * 18))
            elif ev.bit_length() % 8 == 0:
                # full octets - 'dump' view
                sv = ev.dump(center_line=True).split("\n")
                for i in range(0, len(sv)):
                    if i == 0:
                        line = format_line(i_off, n, sv[i])
                    else:
                        line = format_line(i_off, "", sv[i])
                    r.append(line)
                    i_off += 16 * 8
            else:
                # bit-length, just show the bits
                r.append(format_line(i_off, n, f"b{ev.dump()}" + " " * 18))
            bit_off += f.get_bit_length(self.frame, value=v)
        return "\n".join(r)

    def copy(self, parent: Optional[FrameBackend] = None) -> Self:
        raise NotImplementedError()

    def __repr__(self):
        # create a copy to show, so that we do not update state (parent not copied)
        return self.copy().dump(copy_sub_frames=True)


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

    def get_as_frame(self, field: FieldBase[F, T], optional=False) -> Optional[Frame]:
        # FIXME: Not implemented
        if optional:
            return None
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

    def copy(self, parent: Optional[FrameBackend] = None) -> Self:
        n_frame = copy.copy(self.frame)
        c = ComposingBackend(n_frame)
        c.parent = parent
        n_frame.backend = c
        c.mappings = self.mappings  # Note: does not work without parent pointer
        c.changes.update(self.changes)
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
            layer = self.map_layer(field)  # FIXME: Only raw value fields!
            bit_offset = self.get_bit_offset(field.offset)
            data = self.data.tailBits(bit_offset)
            if field.fixed_bit_length < 0 and field.offset.min_tail_length:
                data_len = data.bit_length()
                if data_len >= field.offset.min_tail_length:
                    # limit data length to leave space for the tail
                    data = data.subBlockBits(0, data_len - field.offset.min_tail_length)
            if field.length_resolver:
                f_len = int(field.length_resolver.pull(self))
                data = data.subBlockBits(0, f_len)
            if layer:
                # override field to decode as payload frame
                v = self.decode_as_frame(field, layer, data)
            else:
                v = field.decode(data, self)
            self.value_cache[field] = v
        return v

    def map_layer(self, field: FieldBase) -> Optional[LayerMapping]:
        """Get layer mappings for a raw field, if any"""
        for m in self.mappings:
            mm = m.get_mappings(field)
            if mm:
                return m
        return None

    def decode_as_frame(self, field: FieldBase, mapping: LayerMapping, data: RawData) -> Frame:
        """Decore raw field as a frame with given mappings"""
        f_map = mapping.get_mappings(field)
        for f_ptr, mm in f_map.items():
            value = f_ptr.get(self.frame)
            if value in mm:
                f_type = mm[value]
                v = f_type(self.factory(data))
                return v
        # just raw frame
        return RawFrame(self.factory(data))

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
            cached = self.post_offset.get(prefix.variable_field) if prefix.variable_field else None
            if cached is not None:
                return off + cached
            off += self.get_bit_offset(prefix)
            if prefix.variable_field:
                off += prefix.variable_field.get_bit_length(self.frame)
                self.post_offset[prefix.variable_field] = off
        return off

    def resolve_bit_length(self, field: FieldBase[F, T]) -> int:
        b_len = -1
        if field.fixed_bit_length >= 0:
            # Fixed-length field
            b_len = field.fixed_bit_length
        elif field.length_resolver:
            # Length resolver
            b_len = field.length_resolver.pull(self)
        elif self.map_layer(field):
            # Frame payload, which determines length - FIXME: We should not call map_layer many times!!!
            pass
        elif field.offset.min_tail_length > 0:
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

    def get_as_frame(self, field: FieldBase[F, T], optional=False) -> Optional[Frame]:
        v = self.get(field)
        if isinstance(v, Frame):
            return v
        if optional:
            return None
        if not isinstance(v, RawData):
            # need raw data for a raw frame
            off = self.get_bit_offset(field.offset)
            b_len = self.resolve_bit_length(field)
            v = self.data.subBlockBits(off, b_len)
        return RawFrame(self.factory(v))

    def encode(self) -> RawData:
        bit_length = self.frame.get_bit_length()
        return self.data.subBlockBits(0, bit_length)

    def input_data(self) -> RawData:
        return self.data

    def copy(self, parent: Optional[FrameBackend] = None) -> Self:
        # do not read more data for printing
        limited_data = self.data.subBlockBits(0, self.data.bits_available())

        n_frame = copy.copy(self.frame)
        c = DissectorBackend(n_frame, limited_data)
        c.parent = parent
        n_frame.backend = c
        c.mappings = self.mappings
        c.value_cache.update(self.value_cache)
        return c
