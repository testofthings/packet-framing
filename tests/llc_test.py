from framing.frame_types.ipv4_frames import IPv4
from framing.frame_types.llc_frames import LLC, LLC_Payloads, SNAP_CONTROL, SNAP_SAP
from framing.frames import Frames
from framing.raw_data import Raw


def test_llc_decode():
    data = Raw.hex("aa aa 03 00 00 00 08 00 45 00 00 14")
    llc = LLC(Frames.dissect(data))

    assert LLC.DSAP[llc] == SNAP_SAP
    assert LLC.SSAP[llc] == SNAP_SAP
    assert LLC.Control[llc] == SNAP_CONTROL
    assert LLC.Organization_Code[llc] == Raw.hex("00 00 00")
    assert LLC.Type[llc] == 0x0800
    assert LLC.Data[llc] == Raw.hex("45 00 00 14")
    assert llc.byte_length() == data.byte_length()


def test_llc_payload_mapping():
    data = Raw.hex("aa aa 03 00 00 00 08 00"
                   "45 00 00 14 00 00 00 00 40 11 00 00 c0 a8 a9 01 c0 a8 a9 02")
    llc = LLC(Frames.dissect(data, mappings=LLC_Payloads))

    ip = llc / LLC.Data
    assert isinstance(ip, IPv4)
    assert IPv4.Version[ip] == 4
    assert IPv4.Protocol[ip] == 0x11


def test_llc_encode():
    llc = LLC(Frames.compose())
    LLC.Type[llc] = 0x86dd
    LLC.Data[llc] = Raw.hex("60 00 00 00")

    encoded = llc.encode()
    assert encoded == Raw.hex("aa aa 03 00 00 00 86 dd 60 00 00 00")

    llc = LLC(Frames.dissect(encoded))
    assert LLC.DSAP[llc] == SNAP_SAP
    assert LLC.SSAP[llc] == SNAP_SAP
    assert LLC.Control[llc] == SNAP_CONTROL
    assert LLC.Type[llc] == 0x86dd
    assert LLC.Data[llc] == Raw.hex("60 00 00 00")
