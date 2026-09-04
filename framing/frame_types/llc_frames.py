"""IEEE 802.2 LLC frame definition with SNAP header, and payload mappings"""

from framing.base import Frame, LayerMapping
from framing.codecs import IntegerFormat
from framing.fields import Structure
from framing.frame_types.ipv4_frames import IPv4
from framing.frame_types.ipv6_frames import IPv6

# IEEE Std 802.2 LLC PDU, SNAP encapsulation as in https://www.ietf.org/rfc/rfc1042.txt

# pylint: disable=invalid-name

SNAP_SAP = 0xaa       # DSAP and SSAP value for SNAP
SNAP_CONTROL = 0x03   # Control value for SNAP, unnumbered information


class LLC(Frame):
    """LLC PDU with SNAP header.

    Only the SNAP form is modeled: DSAP and SSAP 0xaa with 1-octet Control 0x03,
    followed by the SNAP Organization Code and Type. Other LLC PDUs have a
    different, possibly 2-octet, Control field and no SNAP header."""
    structure = Structure['LLC']()

    DSAP = structure.integer(bits=8, default=SNAP_SAP)
    SSAP = structure.integer(bits=8, default=SNAP_SAP)
    Control = structure.integer(bits=8, default=SNAP_CONTROL)
    Organization_Code = structure.raw(bytes=3)
    Type = structure.integer(IntegerFormat(bytes=2))  # EtherType, big endian
    Data = structure.raw()


# Define LLC payload type mappings
LLC_Payloads = LayerMapping(LLC.Data).by(LLC.Type, {
    0x0800: IPv4,
    0x86dd: IPv6,
})
