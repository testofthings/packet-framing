from framing.base import Frame
from framing.fields import Structure


class DHCP(Frame):
    structure = Structure['DHCP']()

    op = structure.integer(bits=8)
    htype = structure.integer(bits=8)
    hlen = structure.integer(bits=8)
    hops = structure.integer(bits=8)
    xid = structure.integer(bits=32)
    secs = structure.integer(bits=16)
    flags = structure.raw(bits=16)

    ciaddr = structure.raw(bytes=4)
    yiaddr = structure.raw(bytes=4)
    siaddr = structure.raw(bytes=4)
    giaddr = structure.raw(bytes=4)
    chaddr = structure.raw(bytes=16)  # NOTE: Should apply 'hlen'
    file = structure.raw(bytes=128)

    options = structure.raw()
