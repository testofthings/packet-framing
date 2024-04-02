import copy
from typing import Dict, Any, Callable, Iterator, Optional, List, cast, Type, Tuple, Self

from framing.base import FrameBackend, Frame, EncodingState, Field, F, T, LayerMapping, FieldOffset, FieldPointer
from framing.fields import Sequence, FT, Structure, SubStructureField
from framing.raw_data import RawData, Raw, LengthEntity


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
            if self.choice:
                self.known_bit_length = self.choice.get_bit_length(self.frame)
            else:
                self.known_bit_length = self.get_bit_offset(self.structure.fields_length)
        return self.known_bit_length

    def add_mapping(self, mapping: 'LayerMapping') -> Self:
        mapping.merge(self.mappings)
        return self

    def decode_as_frame(self, mapping: Dict[FieldPointer, Dict[Any, Type[Frame]]], data: RawData) -> Frame:
        for f_ptr, mm in mapping.items():
            value = f_ptr.get(self.frame)
            f_type = mm.get(value)
            if f_type is not None:
                v = f_type(self.factory(data))
                return v
        # just raw frame
        return RawFrame(self.factory(data))

    def dump(self, bit_offset=0, indent='', width=80, copy_sub_frames=False) -> str:
        r = []

        def print_line(offset: int, name: str, data=""):
            s = f"{offset // 8:06x} {indent} "
            s_len = width - 8 - len(indent) - len(name) - len(data)
            if s_len < 1:
                r.append(f"{s}{name}")
                name = ""
                s_len = width - 8 - len(indent) - 0 - len(data)
            s_len = max(0, s_len)
            r.append(s + name + " " * s_len + f"{data}")

        def print_value(offset: int, value: RawData):
            sv = value.dump(center_line=True).split("\n")
            i_off = offset
            for i in range(0, len(sv)):
                if i == 0:
                    print_line(i_off, n, sv[i])
                else:
                    print_line(i_off, "", sv[i])
                i_off += 16 * 8

        state = EncodingState()
        bit_off = bit_offset
        if self.choice is None:
            field_items = self.structure.fields.items()
        else:
            field_items = [(self.choice.field_name, self.choice)]
        for n, f in field_items:
            try:
                v = self.get(f)
            except EOFError as e:
                r.append(f"<<<<<< {e}")
                break
            if isinstance(f, Sequence) and isinstance(f.sub, SubStructureField):
                # Sequence of frames
                for num, i in enumerate(v):
                    be = i.backend
                    if copy_sub_frames:
                        be = be.copy(parent=self)
                    print_line(bit_off, f"{n} {num + 1}/{len(v)}")
                    v_s = be.dump(bit_offset=bit_off, indent=indent + '  ', width=width,
                                  copy_sub_frames=copy_sub_frames)
                    r.append(v_s)
                    bit_off += be.frame.bit_length()
                continue
            if isinstance(f, Sequence):
                # Sequence of values
                for num, v in enumerate(v):
                    ev = f.sub.encode(v, state)
                    print_value(bit_off, ev)
                    bit_off += ev.bit_length()
                continue
            if isinstance(v, RawFrame):
                v = v.encode()
            if isinstance(v, Frame):
                be = v.backend
                if copy_sub_frames:
                    be = be.copy(parent=self)
                print_line(bit_off, f"{n} ({be.structure_name()})")
                v_s = be.dump(bit_offset=bit_off, indent=indent + '  ', width=width, copy_sub_frames=copy_sub_frames)
                r.append(v_s)
                try:
                    bit_off += be.frame.bit_length()
                except EOFError as e:
                    r.append(f"<<<<<< {e}")
                    bit_off += be.input_data().bit_length()
                continue
            ev = f.encode(v, state)
            if ev.bit_length() == 0:
                print_line(bit_off, n, "()" + " " * 18)
            elif ev.bit_length() % 8 == 0:
                # full octets - 'dump' view
                print_value(bit_off, ev)
            else:
                # bit-length, just show the bits
                print_line(bit_off, n, f"b{ev.dump()}" + " " * 18)
            bit_off += f.get_bit_length(self.frame)
        return "\n".join(r)

    def copy(self, parent: Optional[FrameBackend] = None) -> Self:
        raise NotImplementedError()

    def _bad_field_access(self, field: Field) -> str:
        """Create assertion text for field accessing wrong frame"""
        # NOTE: If the field is for non-built frame, we cannot give the proper error message
        return f"{field.structure.structure_name}.{field.field_name} is not field of {self.structure_name()}"

    def __repr__(self):
        # create a copy to show, so that we do not update state (parent not copied)
        return f"{self.structure_name()}\n{self.copy().dump(copy_sub_frames=True)}"


class RawFrame(Frame):
    structure = Structure['RawFrame']()
    data = structure.raw()

    def build_with_lengths(bits: int = None, bytes: int = None, min_bits: int = None, min_bytes: int = None,
                           default: RawData = Raw.empty) -> Type[Frame]:
        """Build raw frame with length limits"""
        class RawFrameWithLength(Frame):
            structure = Structure['RawFrameWithLength']()
            data = structure.raw(bits=bits, bytes=bytes, min_bits=min_bits, min_bytes=min_bytes)
        return RawFrameWithLength


class ComposingBackend(BackendImplementation):
    """Backend to compose a frame"""
    def __init__(self, frame: Frame, mappings: LayerMapping):
        super().__init__(frame, mappings)

    def get(self, field: Field[F, T]) -> T:
        v = self.field_values.get(field)
        if v is None:
            assert field.structure == self.structure, self._bad_field_access(field)
            v = field.get_default_value(self.frame)
            self.field_values[field] = v
        return v

    def set(self, field: Field[F, T], value: T) -> Self:
        assert field.structure == self.structure, self._bad_field_access(field)
        if self.choice:
            # update the choice
            self.field_values.pop(self.choice)
            self.choice = field
        self.field_values[field] = value
        return self

    def get_item(self, sequence_field: Field, item_field: Field[F, FT], index: int):
        val = self.get(sequence_field)
        return val[index]

    def get_as_frame(self, field: Field[F, T], frame_type: Optional[Type[F]] = None,
                     default_frame=False) -> Optional[Frame]:
        # FIXME: Not implemented
        if not default_frame:
            return None
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
            v = self.get(prefix.field)
            off += prefix.field.encoding_bit_length(self, v)
        else:
            off = 0
        off += offset.fixed_bit_offset
        return off

    def encode(self) -> RawData:
        self.structure.commit(self.frame)
        self.known_bit_length = -1
        f_list = []
        state = EncodingState()
        if self.choice:
            v = self.get(self.choice)
            return self.choice.encode(v, state)
        for f in self.structure.fields.values():
            v = self.get(f)
            f_list.append(f.encode(v, state))
        return Raw.sequence(f_list)

    def copy(self, parent: Optional[FrameBackend] = None) -> Self:
        n_frame = copy.copy(self.frame)
        c = ComposingBackend(n_frame, self.mappings)
        c.parent = parent
        c.choice = self.choice
        n_frame.backend = c
        c.field_values.update(self.field_values)
        return c


class DissectorBackend(BackendImplementation):
    """Backend to dissect frame from raw data"""
    def __init__(self, frame: Frame, mappings: LayerMapping, data: RawData):
        super().__init__(frame, mappings)
        self.is_decoder = True
        self.data = data
        self.end_offset_cache: Dict[Field, int] = {}

    def get(self, field: Field[F, T]) -> T:
        v = self.field_values.get(field)
        if v is None:
            v = self.get_not_cached(field)
            self.field_values[field] = v
        return v

    def get_not_cached(self, field: Field[F, T]) -> T:
        assert field.structure == self.structure, self._bad_field_access(field)
        layer_map = self.mappings.get_mappings(field)
        if not layer_map and field.direct_decode:
            v = field.decode_direct(self.data, self)  # quick (hopefully)
            return v
        data, d_len = self.get_raw(field)
        try:
            if layer_map:
                # override field to decode as payload frame
                v = self.decode_as_frame(layer_map, data)
            else:
                v = field.decode(data, d_len, self)
        except EOFError as e:
            raise EOFError(f"{field.field_name} {e}")
        return v

    def get_raw(self, field: Field) -> Tuple[RawData, int]:
        bit_offset = self.get_bit_offset(field.offset)
        bit_length = field.decode_bit_length(self.data, bit_offset, None, self)

        if bit_length < 0 and field.offset.min_tail_length:
            # length not known, limited by space required by later field(s)
            bit_length = max(0, self.data.bit_length() - bit_length - field.offset.min_tail_length)
            bit_length = field._validate_length(bit_length)

        if field.min_bit_length < field.max_bit_length:
            # variable length, check find out how much to read
            avail = self.data.bits_available()
            if avail >= field.max_bit_length:
                # maximum amount of data available
                return self.data.subBlockBits(0, field.max_bit_length), field.max_bit_length
            # less than maximum surely available, must read to find out
            data_len = self.data.bit_length()
            bit_length = field._validate_length(data_len)

        if bit_length < 0:
            data = self.data.tailBits(bit_offset)
        else:
            data = self.data.subBlockBits(bit_offset, bit_length)
        return data, bit_length

    # Editing not allowed for dissected stuff
    # def set(self, field: Field[F, T], value: T) -> Self:

    def get_item(self, sequence_field: Field, item_field: Field[F, FT], index: int):
        v = self.field_values.get(sequence_field)
        if v is not None:
            return v[index]

        bit_offset = self.get_bit_offset(sequence_field.offset)
        i = 0
        while i < index:
            v_len = item_field.decode_bit_length(self.data, bit_offset, None, self)
            assert v_len >= 0, f"Length with unknown length at {index}"
            bit_offset += v_len
            i += 1
        data = self.data.tailBits(bit_offset)
        v = item_field.decode(data, -1, self)
        return v

    def get_bit_offset(self, offset: FieldOffset) -> int:
        prefix = offset.prefix
        if prefix:
            # get offset of the prefix
            field = prefix.field
            off = self.end_offset_cache.get(field)
            if off is None:
                # not found from the cache
                if field.end_offset_resolver:
                    # Note: field.decode_bit_length would also use the resolver, but it needs the offset
                    off = int(field.end_offset_resolver.pull(self))
                else:
                    # prefix offset + variable length
                    off = self.get_bit_offset(prefix)
                    p_len = field.decode_bit_length(self.data, off, None, self)
                    if p_len < 0 and field.min_bit_length < field.max_bit_length and not field.offset.min_tail_length:
                        # maximum length is known
                        if self.data.bit(off + field.max_bit_length - 1) >= 0:
                            # maximum data available
                            p_len = field.max_bit_length
                    if p_len < 0:
                        # no length information, assuming all available
                        p_len = self.data.read_all().bit_length() - off
                        if field.offset.min_tail_length:
                            # data limited by space required by later field(s)
                            p_len = max(0, p_len - field.offset.min_tail_length)
                        p_len = field._validate_length(p_len)
                    off += p_len
                self.end_offset_cache[field] = off  # cache for next call
        else:
            off = 0
        off += offset.fixed_bit_offset
        return off

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
                count=-1, terminator: Optional[Callable[[T], bool]] = None) -> Iterator[FT]:
        v = self.field_values.get(sequence_field)
        if v is not None:
            return v.__iter__()  # already value in memory (we do not store it here)

        backend = self

        class ItemIterator(Iterator[FT]):
            def __init__(self, window: RawData, count: int):
                self.window = window  # sliding to avoid starting from first sub-block each time
                self.count = count
                self.items = 0
                self.previous = None

            def __next__(self) -> Optional[FT]:
                if 0 <= count <= self.items:
                    raise StopIteration()  # hit max. count

                if self.previous is not None:
                    # move buffer to next item
                    v_len = item_field.decode_bit_length(self.window, 0, self.previous, backend)
                    self.window = self.window.tailBits(v_len)

                if self.window.octet(0) < 0:
                    self.count = self.items
                    raise StopIteration()
                v = item_field.decode(self.window, -1, backend)
                self.items += 1
                self.previous = v
                if terminator is not None and terminator(v):
                    self.count = self.items  # hit terminator
                return v

        off = self.get_bit_offset(sequence_field.offset)
        window = self.data.tailBits(off)
        return ItemIterator(window, count)

    def get_as_frame(self, field: Field[F, T], frame_type: Optional[Type[F]] = None,
                     default_frame=False) -> Optional[Frame]:
        if frame_type:
            raw_data, _ = self.get_raw(field)
            return frame_type(self.factory(raw_data))
        v = self.get(field)
        if isinstance(v, Frame):
            return v
        if not default_frame:
            return None
        if not isinstance(v, RawData):
            # need raw data for a raw frame
            v, _ = self.get_raw(field)
        return RawFrame(self.factory(v))

    def encode(self) -> RawData:
        bit_length = self.frame.bit_length()
        return self.data.subBlockBits(0, bit_length)

    def get_bit_length(self) -> int:
        if self.known_bit_length < 0:
            if self.choice is not None:
                rl = self.choice.get_bit_length(self.frame)
            else:
                rl = self.get_bit_offset(self.structure.fields_length)
            if self.data.bit(rl - 1) < 0:
                # input data is known to be shorter...
                raise EOFError(f"Only {self.data.byte_length()} bytes available for " + self.structure_name())
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
        c.choice = self.choice
        n_frame.backend = c
        c.field_values.update(self.field_values)
        return c

    def close(self) -> Self:
        self.data.close()
