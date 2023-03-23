from typing import Tuple

from framing.base import Frame
from framing.fields import Structure, ValueOf
from framing.raw_data import IPAddress


class IPv6(Frame):
    structure = Structure['IPv6']()

    Version = structure.integer(bits=4, default=6)
    Traffic_class = structure.integer(bits=8)
    Flow_label = structure.integer(bits=20)
    Payload_length = structure.integer(bits=16)
    Next_header = structure.integer(bits=8)
    Hop_limit = structure.integer(bits=8)
    Source_address = structure.raw(bytes=16)
    Destination_address = structure.raw(bytes=16)

    Payload = structure.raw().end_offset_by(ValueOf(Payload_length))

    def get_addresses(self) -> Tuple[IPAddress, IPAddress]:
        """Quick access to source and destination address"""
        return self.backend.get(self.Source_address).as_ip_address(), \
            self.backend.get(self.Destination_address).as_ip_address()
