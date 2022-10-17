from typing import Tuple, List

from typing_extensions import Self

from framing.raw_data import RawData, AppendableRawData


class RawDataQueue:
    def __init__(self, prefix: RawData, offset=0):
        self.offset = offset  # bytes
        self.modulus = 2 ^ 32
        self.head = AppendableRawData(prefix)
        # fragment offset relative to self.offset
        self.fragments: List[Tuple[int, RawData]] = []

    # FIXME: Offset wrapping is not working, especially with forwarding!!!

    def push(self, data: RawData, offset: int) -> Self:
        """Push data to end of the queue"""
        # avoid off-set wrapping, trust Python has enough bits in int
        off = (offset + self.modulus - self.offset) % self.modulus
        fix_length = self.head.fixed.byte_length()
        if off < fix_length:
            # part of the data already in
            data = data.tailBytes(fix_length - off)
            if data.byte_length() == 0:
                return self
            off = fix_length
        # add into fragments, do not worry about overlaps for now
        f_i = 0
        while f_i < len(self.fragments):
            f_off, f_data = self.fragments[f_i]
            if off <= f_off:
                self.fragments.insert(f_i, (off, data))
                break
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
        return self

    def forward(self, length) -> Self:
        """Forward offset from beginning of the queue"""
        assert length < self.head.fixed.byte_length(), "Forwarding queue too fast"
        self.head = self.head.tailBytes(length)
        new_offset = (self.offset + length) % self.modulus
        offset_d = new_offset - self.offset
        for i, f in enumerate(self.fragments):
            self.fragments[i] = f[0] - offset_d, f[1]
        self.offset += offset_d
        return self

    def pull(self, length) -> Self:
        """Pull data from beginning of the queue"""
        r = self.head.subBlock(0, length)
        self.forward(length)
        return r
