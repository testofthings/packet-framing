from framing.base import *
from framing.frames import *

# https://datatracker.ietf.org/doc/id/draft-gharris-opsawg-pcap-00.html


class FileHeader(Frame):
    structure = Structure['FileHeader']()

    Magic_Number = structure.raw(bytes=4)
    Major_Version = structure.integer(bytes=2)
    Minor_Version = structure.integer(bytes=2)
    Reserved1 = structure.raw(bytes=4)
    Reserved2 = structure.raw(bytes=4)
    SnapLen = structure.integer(bytes=4)
    LinkType = structure.integer(bytes=4)


class PacketRecord(Frame):
    structure = Structure['PacketRecord']()

    Timestamp_Sec = structure.integer(bytes=4)
    Timestamp_S = structure.integer(bytes=4)
    Captured_Packet_length = structure.integer(bytes=4)
    Original_Packet_length = structure.integer(bytes=4)
    Packet_Data = structure.raw()


class PCAPFile(Frame):
    structure = Structure['PCAPFile']()

    File_Header = structure.sub(FileHeader)
    # Packet_Records = Sequence(structure.sub(PacketRecord))



