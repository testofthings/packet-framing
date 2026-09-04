"""PCAPNG frame definitions and related types.

There is no LayerMapping for the packet data, as the link type of a packet is not in the packet
block itself, but in the interface description block the packet refers to. Use the packet iterator
or the stack layer, which follow the interfaces of the file, to get the link type of a packet."""

import pathlib
from typing import Iterable, Iterator, List, Optional, Tuple

from framing.base import Frame, LayerMapping
from framing.codecs import IntegerFormat
from framing.fields import Selection, Sequence, Structure, ValueOf
from framing.frames import Frames
from framing.layer_stack import StackLayer, StackState
from framing.raw_data import Raw, RawData

# https://datatracker.ietf.org/doc/html/draft-ietf-opsawg-pcapng


# pylint: disable=invalid-name


# PCAPNG integers are least significant octet first, unless the Byte-Order Magic tells otherwise
Int = IntegerFormat(lsb_first=True).swappable()

# The first octets of a file, the Section Header Block type, the same in both octet orders
MAGIC_NUMBER = Raw.hex("0A0D0D0A")

# The Byte-Order Magic of a Section Header Block
BYTE_ORDER_MAGIC = Raw.hex("4D3C2B1A")      # least significant octet first
BYTE_ORDER_MAGIC_MSB = Raw.hex("1A2B3C4D")  # most significant octet first

# The block types which are modeled
BLOCK_SECTION_HEADER = 0x0a0d0d0a
BLOCK_INTERFACE_DESCRIPTION = 0x00000001
BLOCK_SIMPLE_PACKET = 0x00000003
BLOCK_ENHANCED_PACKET = 0x00000006

# The block type, the block total length, and the total length repeated at the end
BLOCK_FRAMING_LENGTH = 12

# The PCAPNG file format version we can read. A new minor version is backward compatible.
MAJOR_VERSION = 1
MINOR_VERSION = 0


def is_msb_first(data: RawData) -> bool:
    """Is the PCAPNG file data most significant octet first? Told by the Byte-Order Magic."""
    return data.sub_block(8, 4) == BYTE_ORDER_MAGIC_MSB


class SectionHeaderBlock(Frame):
    """PCAPNG Section Header Block body"""
    structure = Structure['SectionHeaderBlock']()

    Byte_Order_Magic = structure.raw(bytes=4, default=BYTE_ORDER_MAGIC)
    Major_Version = structure.integer(Int.bytes(2), default=MAJOR_VERSION)
    Minor_Version = structure.integer(Int.bytes(2), default=MINOR_VERSION)
    Section_Length = structure.integer(Int.bytes(8))
    Options = structure.raw()


class InterfaceDescriptionBlock(Frame):
    """PCAPNG Interface Description Block body"""
    structure = Structure['InterfaceDescriptionBlock']()

    LinkType = structure.integer(Int.bytes(2))
    Reserved = structure.raw(bytes=2)
    SnapLen = structure.integer(Int.bytes(4))
    Options = structure.raw()


class EnhancedPacketBlock(Frame):
    """PCAPNG Enhanced Packet Block body"""
    structure = Structure['EnhancedPacketBlock']()

    Interface_ID = structure.integer(Int.bytes(4))
    Timestamp_High = structure.integer(Int.bytes(4))
    Timestamp_Low = structure.integer(Int.bytes(4))
    Captured_Packet_Length = structure.integer(Int.bytes(4))
    Original_Packet_Length = structure.integer(Int.bytes(4))
    Packet_Data = structure.raw().length_by(
        ValueOf(Captured_Packet_Length).copy_to(Original_Packet_Length))
    Options = structure.raw()  # the padding of the packet data is part of this


class SimplePacketBlock(Frame):
    """PCAPNG Simple Packet Block body"""
    structure = Structure['SimplePacketBlock']()

    Original_Packet_Length = structure.integer(Int.bytes(4))
    Packet_Data = structure.raw()  # the captured data with its padding, no options in this block


class BlockBody(Frame):
    """The body of a block, by the block type"""
    structure = Selection['BlockBody']()

    Other = structure.raw()  # block types which are not modeled, e.g. Name Resolution Block
    Interface_Description = structure.choice(BLOCK_INTERFACE_DESCRIPTION,
                                             structure.sub(InterfaceDescriptionBlock))
    Simple_Packet = structure.choice(BLOCK_SIMPLE_PACKET, structure.sub(SimplePacketBlock))
    Enhanced_Packet = structure.choice(BLOCK_ENHANCED_PACKET, structure.sub(EnhancedPacketBlock))
    Section_Header = structure.choice(BLOCK_SECTION_HEADER, structure.sub(SectionHeaderBlock))


class Block(Frame):
    """PCAPNG block"""
    structure = Structure['Block']()

    Block_Type = structure.integer(Int.bytes(4))
    Block_Total_Length = structure.integer(Int.bytes(4))
    Body = structure.sub(BlockBody).choice_by(ValueOf(Block_Type))
    Block_Total_Length_2 = structure.integer(Int.bytes(4))


# The body is the block without the framing. The total length is repeated at the end of a block,
# it is configured here, as the field is not yet defined inside the class.
Block.Body.length_by(ValueOf(Block.Block_Total_Length).copy_to(Block.Block_Total_Length_2)
                     - BLOCK_FRAMING_LENGTH)


class PCAPNGFile(Frame):
    """PCAPNG file"""
    structure = Structure['PCAPNGFile']()

    Blocks = Sequence(structure.sub(Block))

    def check_format(self) -> 'PCAPNGFile':
        """Check that this is a PCAPNG file we can read. Raises ValueError, if it is not."""
        try:
            block = PCAPNGFile.Blocks.item(self, 0)
            block_type = Block.Block_Type[block]
            header = Block.Body.get_choice(block)
        except EOFError as e:
            raise ValueError("The file is too short to be a PCAPNG file") from e
        if not isinstance(header, SectionHeaderBlock):
            raise ValueError(f"Not a PCAPNG file, the first block type is {block_type:#010x}")
        magic = SectionHeaderBlock.Byte_Order_Magic[header]
        if magic not in (BYTE_ORDER_MAGIC, BYTE_ORDER_MAGIC_MSB):
            raise ValueError(f"Unknown PCAPNG Byte-Order Magic {magic.to_hex()}")
        major = SectionHeaderBlock.Major_Version[header]
        minor = SectionHeaderBlock.Minor_Version[header]
        if major != MAJOR_VERSION:
            raise ValueError(f"Unsupported PCAPNG file version {major}.{minor}, "
                             f"version {MAJOR_VERSION}.{MINOR_VERSION} is supported")
        return self

    @classmethod
    def open_file(cls, file: pathlib.Path, mappings: Optional[LayerMapping] = None) -> 'PCAPNGFile':
        """Open and dissect a PCAPNG file"""
        data = Raw.file(file)
        f = PCAPNGFile(Frames.dissect(data, int_swap=is_msb_first(data)))
        return Frames.check_file(f, PCAPNGFile.check_format, mappings)


def packet_data(block: Block) -> RawData:
    """The packet data of a packet block"""
    body = Block.Body.get_choice(block)
    if isinstance(body, EnhancedPacketBlock):
        return EnhancedPacketBlock.Packet_Data[body]
    if isinstance(body, SimplePacketBlock):
        data = SimplePacketBlock.Packet_Data[body]
        # the block does not tell the captured length, the data is padded to a multiple of four
        length = min(SimplePacketBlock.Original_Packet_Length[body], data.byte_length())
        return data.sub_block(0, length)
    raise ValueError(f"Block type {Block.Block_Type[block]:#010x} does not hold packet data")


class PCAPNGPacketIterator(Iterator[Tuple[Block, int]]):
    """Iterate the packet blocks of a PCAPNG file as (block, link type) pairs"""
    def __init__(self, file: PCAPNGFile) -> None:
        self.blocks = PCAPNGFile.Blocks.iterate(file)
        self.link_types: List[int] = []

    def __next__(self) -> Tuple[Block, int]:
        for block in self.blocks:
            body = Block.Body.get_choice(block)
            if isinstance(body, SectionHeaderBlock):
                self.link_types.clear()  # a new section, the interfaces are described again
            elif isinstance(body, InterfaceDescriptionBlock):
                self.link_types.append(InterfaceDescriptionBlock.LinkType[body])
            elif isinstance(body, EnhancedPacketBlock):
                return block, self.link_type(EnhancedPacketBlock.Interface_ID[body])
            elif isinstance(body, SimplePacketBlock):
                return block, self.link_type(0)  # the block has no interface, the first one it is
        raise StopIteration

    def link_type(self, interface_id: int) -> int:
        """The link type of an interface of the current section"""
        if interface_id >= len(self.link_types):
            raise ValueError(f"PCAPNG interface {interface_id} is not described in the file")
        return self.link_types[interface_id]


class PCAPNGStackLayer(StackLayer):
    """PCAPNG stack layer"""
    def __init__(self) -> None:
        super().__init__(PCAPNGFile)

    def receive(self, state: StackState) -> Iterable[StackState]:
        file = PCAPNGFile(Frames.dissect(state.data, int_swap=is_msb_first(state.data)))
        file.check_format()
        state = state.add(file)
        for block, link_type in PCAPNGPacketIterator(file):
            yield state.add(block, link_type, packet_data(block))
