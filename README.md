# Packet framing

This is a small network frame parsing module implemented for parsing PCAP files in [Tcsfw](https://github.com/ouspg/tcsfw).
The supported protocols and packet formats are those required by the project.
At the moment, this is not too many, so this most likely is not the software you are looking for.

## PyPi

The module [packet-framing](https://pypi.org/project/packet-framing/) is published in _Python Package Index_ (PyPI).
Installation from there should be as easy or hard as any other Python package.

## Supported protocols and formats

The following protocol formats are supported. 

## Command-line use

The project comes with experimental PCAP dissection tool used in development and testing of the framework.

NOTE: Tool documentation under construction.

## Basic concepts

A protocol packet is modeled as a Python class.
For example, consider the definition of the _IPv4 datagram_ from file `framing/frame_types/ipv4_frames.py`:

```python
class IPv4(Frame):
    structure = Structure['IPv4']()

    Version = structure.integer(IntegerFormat(bits=4), default=4)
    IHL = structure.integer(IntegerFormat(bits=4))
    DSCP = structure.integer(IntegerFormat(bits=6))
    ECN = structure.integer(IntegerFormat(bits=2))
    Total_Length = structure.integer(IntegerFormat(bits=16))
    Identification = structure.raw(bits=16)
    Flags = structure.integer(IntegerFormat(bits=3))
    Fragment_Offset = structure.integer(IntegerFormat(bits=13))
    TTL = structure.integer(IntegerFormat(bits=8))
    Protocol = structure.integer(IntegerFormat(bits=8))
    Header_Checksum = structure.integer(IntegerFormat(bits=16))
    Source_IP = structure.raw(bits=32)
    Destination_IP = structure.raw(bits=32)

    Options = structure.raw().end_offset_by(ValueOf(IHL) * 4)

    Payload = structure.raw().end_offset_by(ValueOf(Total_Length))

```
