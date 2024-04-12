"""DHCP (Dynamic Host Configuration Protocol)"""

from framing.base import Frame
from framing.fields import Structure


class DHCP(Frame):
    """DHCP packet"""
    structure = Structure['DHCP']()

    op = structure.integer(bits=8)
    htype = structure.integer(bits=8)
    hlen = structure.integer(bits=8)
    hops = structure.integer(bits=8)
    xid = structure.integer(bits=32)
    secs = structure.integer(bits=16)
    flags = structure.raw(bits=16)

    ciaddr = structure.raw(octets=4)
    yiaddr = structure.raw(octets=4)
    siaddr = structure.raw(octets=4)
    giaddr = structure.raw(octets=4)
    chaddr = structure.raw(octets=16)  # NOTE: Should apply 'hlen'
    file = structure.raw(octets=128)

    options = structure.raw()
