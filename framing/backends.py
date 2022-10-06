import copy
from typing import Dict, Any, Callable, Iterator, Optional, List, cast, Type

from typing_extensions import Self

from framing.base import FrameBackend, Frame, EncodingState, Field, F, T, LayerMapping, FieldOffset, FieldPointer
from framing.fields import Sequence, FT, Structure
from framing.raw_data import RawData, Raw


class BackendImplementation(FrameBackend):
    def __init__(self, frame: Frame, mappings: LayerMapping):
        super().__init__(frame)
        self.mappings = mappings
        self.known_bit_length = -1
        self.field_values: Dict[Field, Any] = {}

    @classmethod
    def list_resolved_fields(cls, frame: Frame) -> List[Field]:
        """List resolved fields for unit tests"""
        be = cast(BackendImplementation, frame.backend)
        return sorted(be.field_values.keys())

    def get_bit_length(self) -> int:
        if self.known_bit_length < 0:
            self.known_bit_length = self.get_bit_offset(self.structure.fields_length)
        return self.known_bit_length

    def add_mapping(self, mapping: 'LayerMapping') -> Self:
        mapping.merge(self.mappings)
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
            if isinstance(v, RawFrame):
                v = v.encode()
            if isinstance(v, Frame):
                be = v.backend
                if copy_sub_frames:
                    be = be.copy(parent=self)
                r.append(format_line(i_off, f"{n} ({be.structure_name()})"))
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
    def __init__(self, frame: Frame, mappings: LayerMapping):
        super().__init__(frame, mappings)

    def get(self, field: Field[F, T]) -> T:
        v = self.field_values.get(field)
        if v is None:
            v = field.get_default_value(self.frame)
            self.field_values[field] = v
        return v

    def set(self, field: Field[F, T], value: T) -> Self:
        self.field_values[field] = value
        return self

    def get_item(self, sequence_field: Field, item_field: Field[F, FT], index: int):
        val = self.get(sequence_field)
        return val[index]

    def get_as_frame(self, field: Field[F, T], frame_type: Optional[Type[F]] = None) -> Optional[Frame]:
        # FIXME: Not implemented
        return RawFrame(self.factory())

    def factory(self, decode: RawData = None) -> Callable[[Frame], FrameBackend]:
        def f(frame: Frame):
            b = ComposingBackend(frame, self.mappings)
            b.parent = self
            return b
        return f

    def get_bit_offset(self, offset: FieldOffset) -> int:
        prefix = offset.prefix
        if prefix:
            # get offset of the prefix
            off = self.get_bit_offset(prefix)
            # add prefix variable length to it
            off += prefix.field.get_bit_length(self.frame)
        else:
            off = 0
        off += offset.fixed_bit_offset
        return off

    def resolve_bit_length(self, field: Field[F, T]) -> int:
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
        c = ComposingBackend(n_frame, self.mappings)
        c.parent = parent
        n_frame.backend = c
        c.field_values.update(self.field_values)
        return c


class DissectorBackend(BackendImplementation):
    """Backend to dissect frame from raw data"""
    def __init__(self, frame: Frame, mappings: LayerMapping, data: RawData):
        super().__init__(frame, mappings)
        self.is_decoding = True
        self.data = data
        self.end_offset_cache: Dict[Field, int] = {}

    def get(self, field: Field[F, T]) -> T:
        v = self.field_values.get(field)
        if v is None:
            data = self.get_raw(field)
            layer_map = self.mappings.get_mappings(field)
            if layer_map:
                # override field to decode as payload frame
                v = self.decode_as_frame(field, layer_map, data)
            else:
                v = field.decode(data, self)
            self.field_values[field] = v
        return v

    def get_raw(self, field: Field) -> RawData:
        bit_offset = self.get_bit_offset(field.offset)
        bit_length = -1

        if field.fixed_bit_length < 0:
            # variable length field
            if field.end_offset_resolver:
                # end offset resolver
                bit_length = int(field.end_offset_resolver.pull(self)) - bit_offset
            elif field.length_resolver:
                # field length resolver
                bit_length = int(field.length_resolver.pull(self))

            if field.offset.min_tail_length:
                data_len = self.data.bit_length()
                end_offset = bit_offset + max(0, bit_length)
                if data_len - end_offset > field.offset.min_tail_length:
                    # limit data length to leave space for the tail
                    bit_length = data_len - field.offset.min_tail_length - bit_offset
        else:
            # constant length field
            bit_length = field.fixed_bit_length

        if bit_length < 0:
            data = self.data.tailBits(bit_offset)
        else:
            data = self.data.subBlockBits(bit_offset, bit_length)
        return data

    def decode_as_frame(self, field: Field, mapping: Dict[FieldPointer, Dict[Any, Type[Frame]]], data: RawData) -> Frame:
        """Decore raw field as a frame with given mappings"""
        for f_ptr, mm in mapping.items():
            value = f_ptr.get(self.frame)
            f_type = mm.get(value)
            if f_type is not None:
                v = f_type(self.factory(data))
                return v
        # just raw frame
        return RawFrame(self.factory(data))

    def set(self, field: Field[F, T], value: T) -> Self:
        raise NotImplementedError("set() not supported")

    def get_item(self, sequence_field: Field, item_field: Field[F, FT], index: int):
        v = self.field_values.get(sequence_field)
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
        prefix = offset.prefix
        if prefix:
            # get offset of the prefix
            off = self.end_offset_cache.get(prefix.field)
            if off is None:
                # not found from the cache
                if prefix.field.end_offset_resolver:
                    off = int(prefix.field.end_offset_resolver.pull(self))
                else:
                    # prefix offset + variable length
                    off = self.get_bit_offset(prefix)
                    off += prefix.field.get_bit_length(self.frame)
                self.end_offset_cache[prefix.field] = off  # cache for next call
        else:
            off = 0
        off += offset.fixed_bit_offset
        return off

    def resolve_bit_length(self, field: Field[F, T]) -> int:
        b_len = -1
        if field.fixed_bit_length >= 0:
            # Fixed-length field
            b_len = field.fixed_bit_length
        elif field.length_resolver:
            # Length resolver
            b_len = field.length_resolver.pull(self)
        elif self.mappings.is_mapped(field):
            # Frame payload, which determines length
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
                b = ComposingBackend(frame, self.mappings)
            else:
                b = DissectorBackend(frame, self.mappings, decode)
            b.parent = self
            return b
        return f

    def iterate(self, sequence_field: Field, item_field: Field[F, FT],
                count=-1, terminator: Optional[T] = None) -> Iterator[FT]:
        v = self.field_values.get(sequence_field)
        if v is not None:
            return v.__iter__()  # already value in memory (we do not store it here)

        backend = self
        data = self.data

        class ItemIterator(Iterator[FT]):
            def __init__(self, offset: int, count: int):
                self.offset = offset
                self.count = count
                self.items = 0

            def __next__(self) -> Optional[FT]:
                if 0 <= count <= self.items:
                    raise StopIteration()
                n_data = data.tailBits(self.offset)
                if n_data.octet(0) < 0:
                    raise StopIteration()
                v = item_field.decode(n_data, backend)
                self.offset += v.get_bit_length()
                if terminator == v:
                    self.count = self.items
                    raise StopIteration()
                self.items += 1
                return v

        off = self.get_bit_offset(sequence_field.offset)
        return ItemIterator(off, count)

    def get_as_frame(self, field: Field[F, T], frame_type: Optional[Type[F]] = None) -> Optional[Frame]:
        if frame_type:
            raw_data = self.get_raw(field)
            return frame_type(self.factory(raw_data))
        v = self.get(field)
        if isinstance(v, Frame):
            return v
        if not isinstance(v, RawData):
            # need raw data for a raw frame
            off = self.get_bit_offset(field.offset)
            b_len = self.resolve_bit_length(field)
            v = self.data.subBlockBits(off, b_len)
        return RawFrame(self.factory(v))

    def encode(self) -> RawData:
        bit_length = self.frame.get_bit_length()
        return self.data.subBlockBits(0, bit_length)

    def get_bit_length(self) -> int:
        if self.known_bit_length < 0:
            rl = self.get_bit_offset(self.structure.fields_length)
            if 0 <= self.data.bit_length() < rl:
                # input data is known to be shorter...
                rl = self.data.bit_length()
            self.known_bit_length = rl
        return self.known_bit_length

    def input_data(self) -> RawData:
        return self.data

    def copy(self, parent: Optional[FrameBackend] = None) -> Self:
        # do not read more data for printing
        limited_data = self.data.subBlockBits(0, self.data.bits_available())

        n_frame = copy.copy(self.frame)
        c = DissectorBackend(n_frame, self.mappings, limited_data)
        c.parent = parent
        n_frame.backend = c
        c.field_values.update(self.field_values)
        return c

    def close(self) -> Self:
        self.data.close()
