from framing.base import *
from framing.frames import *

# https://datatracker.ietf.org/doc/id/draft-gharris-opsawg-pcap-00.html

Int = IntegerFormat().big_endian()  # big endian integers


class FileHeader(Frame):
    structure = Structure['FileHeader']()

    Magic_Number = structure.raw(bytes=4, default=Raw.hex("D4C3B2A1"))
    Major_Version = structure.integer(Int.bytes(2), default=2)
    Minor_Version = structure.integer(Int.bytes(2), default=4)
    Reserved1 = structure.raw(bytes=4)
    Reserved2 = structure.raw(bytes=4)
    SnapLen = structure.integer(Int.bytes(4))
    LinkType = structure.integer(Int.bytes(4))


class PacketRecord(Frame):
    structure = Structure['PacketRecord']()

    Timestamp = structure.integer(Int.bytes(4))
    Timestamp_2 = structure.integer(Int.bytes(4))
    Captured_Packet_length = structure.integer(Int.bytes(4))
    Original_Packet_length = structure.integer(Int.bytes(4))
    Packet_Data = structure.raw().length_by(Captured_Packet_length)


class PCAPFile(Frame):
    structure = Structure['PCAPFile']()

    File_Header = structure.sub(FileHeader)
    Packet_Records = Sequence(structure.sub(PacketRecord))



