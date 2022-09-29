import copy
from typing import Dict, Any, cast, Callable

from typing_extensions import Self

from framing.base import Frame, FrameBackend, FieldBase, F, T, EncodingState
from framing.raw_data import RawData, Raw


class BackendImplementation(FrameBackend):
    def __init__(self, frame: Frame):
        super().__init__(frame)

    def pretty_print(self, indent='') -> str:
        r = []
        name_space = max([len(n) for n in self.structure.fields.keys()]) + 1
        state = EncodingState()
        bit_off = 0
        for n, f in self.structure.fields.items():
            i_off = bit_off
            v = self.get(f)
            if isinstance(v, Frame):
                line = f"{i_off // 8:06x} {indent}"
                line += n + " " * (name_space - len(n))
                r.append(line)
                v_s = f"{v}"
                r.extend([f"{s[:6]}  {s[6:]}" for s in v_s.split("\n")])
                continue
            ev = f.encode(v, state)
            sv = ev.dump(always_wide=True).split("\n")
            for i in range(0, len(sv)):
                line = f"{i_off // 8:06x} {indent}"
                if i == 0:
                    line += n + " " * (name_space - len(n))
                else:
                    line += " " * name_space
                line += sv[i]
                r.append(line)
                i_off += 16 * 8
            bit_off += f.get_bit_length(self.frame, value=v)
        return "\n".join(r)


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

    def factory(self, decode: RawData = None) -> Callable[[Frame], FrameBackend]:
        def f(frame: Frame):
            return ComposingBackend(frame)
        return f

    def encode(self) -> RawData:
        self.structure.commit(self.frame)
        f_list = []
        state = EncodingState()
        for f in self.structure.fields.values():
            v = self.get(f)
            f_list.append(f.encode(v, state))
        return Raw.merge(f_list)

    def __repr__(self):
        # create a copy to show, so that we do not update state
        c = self.copy()
        c.encode()
        return c.pretty_print()

    def copy(self) -> Self:
        n_frame = copy.copy(self.frame)
        c = ComposingBackend(n_frame)
        n_frame.backend = c
        c.changes.update(self.changes)
        return c


class DissectorBackend(BackendImplementation):
    """Backend to dissect frame from raw data"""
    def __init__(self, frame: Frame, data: RawData):
        super().__init__(frame)
        self.is_decoding = True
        self.data = data
        self.cache: Dict[FieldBase, Any] = {}

    def get(self, field: FieldBase[F, T]) -> T:
        v = self.cache.get(field)
        if v is None:
            bit_offset = self._field_offset(field)
            data = self.data.tailBits(bit_offset)
            if field.decode_length_procedure:
                f_len = field.decode_length_procedure(self.frame)
                data = data.subBlockBits(0, f_len)
            if field.length_resolver:
                f_len = field.length_resolver.pull(self)
                data = data.subBlockBits(0, f_len)
            v = field.decode(data, self)
            self.cache[field] = v
        return v

    def _field_offset(self, field: FieldBase) -> int:
        off = field.offset.fixed_bit_offset
        prefix = field.offset.prefix
        if prefix:
            # resolve prefix dynamic length
            off += prefix.get_offset(self)
            if prefix.variable_field:
                if prefix.variable_field.decode_length_procedure:
                    f_len = prefix.variable_field.decode_length_procedure(self.frame)
                    off += f_len
                else:
                    # NOTE: We could check if value is cached and provide it
                    off += prefix.variable_field.get_bit_length(self.frame)
        return off

    def set(self, field: FieldBase[F, T], value: T) -> Self:
        raise NotImplementedError("set() not supported")

    def factory(self, decode: RawData = None) -> Callable[[Frame], FrameBackend]:
        def f(frame: Frame):
            if decode is None:
                return ComposingBackend(frame)
            return DissectorBackend(frame, decode)
        return f

    def encode(self) -> RawData:
        bit_length = self.frame.get_bit_length()
        return self.data.tailBits(bit_length)

    def input_data(self) -> RawData:
        return self.data

    def __repr__(self):
        # create a copy to show, so that we do not update state
        c = self.copy()
        return c.pretty_print()

    def copy(self) -> Self:
        # do not read more data for printing
        limited_data = self.data.subBlockBits(0, self.data.bits_available())

        n_frame = copy.copy(self.frame)
        c = DissectorBackend(n_frame, limited_data)
        n_frame.backend = c
        c.cache.update(self.cache)
        return c
