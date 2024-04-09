from typing import Tuple, List, Self

from framing.raw_data import RawData, AppendableRawData, Raw


class RawDataQueue:
    def __init__(self, prefix: RawData = None, offset=0, modulus=2 ** 32):
        self.offset = offset  # bytes
        self.modulus = modulus
        self.head = AppendableRawData(prefix or Raw.empty)
        # fragment offset relative to self.offset
        self.fragments: List[Tuple[int, RawData]] = []

    # FIXME: Offset wrapping is not working, especially with forwarding!!!

    def push(self, data: RawData, offset: int = None) -> RawData:
        """Push data to end of the queue"""
        if offset is None:
            # as default, continuous data
            offset = self.offset + self.head.bytes_available()
        # avoid off-set wrapping, trust Python has enough bits in int
        off = (offset + self.modulus - self.offset) % self.modulus
        fix_length = self.head.fixed.byte_length()
        if off < fix_length:
            # part of the data already in
            data = data.tailBytes(fix_length - off)
            if data.byte_length() == 0:
                return data
            off = fix_length
        # add into fragments, do not worry about overlaps for now
        f_i = 0
        while f_i < len(self.fragments):
            f_off, f_data = self.fragments[f_i]
            if off <= f_off:
                self.fragments.insert(f_i, (off, data))
                break
            f_i += 1
        else:
            self.fragments.append((off, data))
        # check if more stuff to head
        head_len = self.head.fixed.byte_length()
        while self.fragments and self.fragments[0][0] <= head_len:
            f_off, f_data = self.fragments[0]
            add_data = f_data.tailBytes(head_len - f_off)
            self.head.append(add_data)
            self.fragments = self.fragments[1:]
            head_len += add_data.byte_length()
        return data

    def forward(self, length) -> Self:
        """Forward offset from beginning of the queue"""
        assert length <= self.head.fixed.byte_length(), "Forwarding queue too fast"
        self.head = self.head.forward(length)
        new_offset = (self.offset + length) % self.modulus
        offset_d = new_offset - self.offset
        for i, f in enumerate(self.fragments):
            self.fragments[i] = f[0] - offset_d, f[1]
        self.offset += offset_d
        return self

    def available(self) -> int:
        """Get byte length of available data"""
        return self.head.fixed.byte_length()

    def pull(self, byte_length: int) -> RawData:
        """Pull data from beginning of the queue"""
        r = self.head.subBlock(0, byte_length)
        self.forward(byte_length)
        return r

    def pull_all(self) -> RawData:
        """Pull all data from beginning of the queue"""
        return self.pull(self.available())

    def close(self):
        self.head.closed = True

    def is_closed(self) -> bool:
        return self.head.closed

    def __repr__(self):
        r = [
            f"offset={self.offset} length={self.head.bytes_available()}",
            f"{self.head}"
        ]
        for off, f in self.fragments:
            r.append(f"offset=+{off} length={f.byte_length()}")
            r.append(f"{f}")
        return "\n".join(r)
