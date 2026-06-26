# Architecture: Packet Framing

## Overview

This module, `packet-framing` is a declarative, reflection-based framework for modeling, encoding, and decoding binary network protocol frames in Python.

A protocol is described as a plain Python class. Field declarations at class level serve as both the schema and the runtime accessors. The same class is used for encoding (composing) and decoding (dissecting), with the active backend determining which operation is performed.

```
Protocol model (Frame subclass)
          │
          ├── Structure / Selection  ← field schema, resolved once per class
          │       └── Field objects  ← type, bit-width, length constraints
          │
          ├── FrameBackend           ← runtime state (composing or dissecting)
          │       ├── ComposingBackend
          │       └── DissectorBackend
          │
          └── LayerMapping           ← cross-layer payload type dispatch
```

---

## Module layout

| Path | Responsibility |
|---|---|
| `framing/base.py` | Core abstractions: `Frame`, `FrameStructure`, `FrameBackend`, `LayerMapping`, `FieldOffset`, `Calculator` |
| `framing/fields.py` | Concrete field types and the `Structure` / `Selection` builders |
| `framing/codecs.py` | Low-level integer encode/decode codecs (`IntegerCodec`, `IntegerFormat`) |
| `framing/backends.py` | `ComposingBackend`, `DissectorBackend`, `RawFrame` |
| `framing/frames.py` | `Frames` utility class — factory helpers for composing, dissecting, dumping |
| `framing/raw_data.py` | `RawData`, `Raw` — immutable byte-buffer abstraction; `IPAddress` type alias |
| `framing/data_queue.py` | `RawDataQueue` — streaming byte queue for TCP reassembly |
| `framing/layer_stack.py` | `FrameStack`, `StackLayer`, `StackState` — multi-layer dissection pipeline |
| `framing/frame_processors.py` | Higher-level processor combinators (PCAP → Ethernet → IP → TCP/UDP) |
| `framing/frame_types/` | Concrete protocol models (Ethernet, IPv4/v6, TCP, UDP, DNS, TLS, PCAP) |

---

## How a protocol model is described

### 1. Declare a `Frame` subclass

Every protocol is a subclass of `Frame`. A shared class-level `Structure` object collects the fields in declaration order.

```python
from framing.base import Frame
from framing.fields import Structure
from framing.codecs import IntegerFormat

class TCP(Frame):
    structure = Structure['TCP']()           # one Structure per class

    Source_port      = structure.integer(IntegerFormat(bits=16))
    Destination_port = structure.integer(IntegerFormat(bits=16))
    Sequence_number  = structure.integer(IntegerFormat(bits=32))
    Ack_number       = structure.integer(IntegerFormat(bits=32))
    Data_offset      = structure.integer(IntegerFormat(bits=4))
    Reserved         = structure.integer(IntegerFormat(bits=3))
    Flags            = structure.integer(IntegerFormat(bits=9))
    Window           = structure.integer(IntegerFormat(bits=16))
    Checksum         = structure.raw(bits=16)
    Urgent_Pointer   = structure.integer(IntegerFormat(bits=16))
    Options          = structure.raw().end_offset_by(ValueOf(Data_offset) * 4)
    Data             = structure.raw()
```

The `Structure` factory methods return typed `Field` objects, which become class attributes. Field names are discovered by Python reflection (`inspect.getmembers`) the first time a backend is created for the class — this lazy step is called *finishing the build*.

### 2. Field types

| Field type | Builder method | Stores |
|---|---|---|
| `IntField` | `structure.integer(...)` | `int` |
| `RawField` | `structure.raw(...)` | `RawData` |
| `SubStructureField` | `structure.sub(FrameType)` | nested `Frame` |
| `LVField` | wraps another field with `.lv(...)` | length-prefixed value |
| `Sequence` | `Sequence(structure.sub(...))` | `List[T]` |

All field types inherit from `ConfigurableField → Field → FieldPointer`. A field object is both a schema node and a **typed accessor** — `IPv4.Version[frame]` reads the value directly.

### 3. Variable-length fields — the `Calculator` chain

Fields whose bit-width depends on other fields use a composable **calculator** chain to resolve lengths at runtime.

```python
# TCP: Options field ends where Data_offset * 4 bytes puts us
Options = structure.raw().end_offset_by(ValueOf(Data_offset) * 4)

# TLS: fragment length comes from an explicit length field
fragment = structure.raw().length_by(ValueOf(length))

# DNS: a sequence whose item count comes from a header field
Question = Sequence(structure.sub(DNSQuestion)).count_by(
    DNSHeader.QDCOUNT.of(Header)   # cross-field path
)
```

`ValueOf(field)` wraps a field as a `Calculator` source. Arithmetic operators (`*`, `/`) append `Multiplier` nodes. `FieldPath` (written `field_a / field_b`) traverses nested frames to reach a field in a parent or child structure.

During **encoding**, the same calculator chain is run in reverse (`push`) to write the computed length back into the header field.

### 4. `Selection` — discriminated unions

When a field can hold one of several mutually exclusive sub-frames (e.g., DNS RDATA, TLS handshake messages), use `Selection` instead of `Structure`:

```python
class RDATA(Frame):
    structure = Selection['RDATA']()

    Other = structure.raw()                         # default / fallback
    A     = structure.choice(1,  structure.raw(bytes=4))
    NS    = structure.choice(2,  DNSName(structure))
    CNAME = structure.choice(5,  DNSName(structure))
    SOA   = structure.choice(6,  structure.sub(SOA_RDATA))
    AAAA  = structure.choice(28, structure.raw(bytes=16))
```

The active choice is resolved by `choice_by(discriminator_field)` on the parent's `SubStructureField`:

```python
RDATA = structure.sub(RDATA).choice_by(TYPE).length_by(RDLENGTH)
```

At decode time the discriminator integer is looked up in the selection's `choice_map`; at encode time the reverse map writes the discriminator back.

### 5. Nested frames — `SubStructureField`

A `structure.sub(ChildFrame)` field embeds a complete child frame inline. The child's own length resolution is independent of the parent's. Accessing the child via `frame / ChildFrame.some_field` traverses the sub-frame transparently.

### 6. Commit procedures

Encoding requires filling in length and type fields that are derived from other parts of the frame. `ConfigurableField` and `Structure` support registering **commit procedures** — callbacks that run after the frame is fully composed:

```python
# Automatically registered by .length_by(...)
def procedure(frame: F) -> None:
    v = frame.backend.get(field)
    f_len = field.encoding_bit_length(frame.backend, v)
    length_resolver.push(frame.backend, f_len)
structure.commit_procedures.append((field, procedure))
```

`.at_commit(fn)` is the public API for custom procedures.

---

## Backend pattern

`FrameBackend` is the runtime half of a frame. It stores field values, answers read/write requests, and knows the current byte buffer.

```
Frame(backend_factory)
  └── backend: FrameBackend
        ├── ComposingBackend  — mutable dict of field values, encodes on demand
        └── DissectorBackend  — wraps a RawData buffer, decodes lazily
```

Backends are created via factory functions, not constructors, so the same `Frame` class is instantiated the same way in both directions:

```python
# Decode from bytes
frame = IPv4(Frames.dissect(raw_data))

# Encode (compose) from scratch
frame = IPv4(Frames.compose())
IPv4.Version[frame] = 4
IPv4.TTL[frame]     = 64
```

`Frames.compose()` and `Frames.dissect(data)` return `Callable[[Frame], FrameBackend]` — the lambda is called inside `Frame.__init__`.

---

## Field offset resolution

`FrameStructure._resolve_offsets()` walks the field list once after the build step and constructs a linked-list of `FieldOffset` nodes. Each node records:

- `fixed_bit_offset` — accumulated fixed bits from earlier fixed-length fields
- `prefix` — the `FieldOffset` of the last variable-length field before this one
- `min_tail_length` — minimum bits known to follow (used for early EOF detection)

At runtime, `DissectorBackend.get_bit_offset(offset)` walks the prefix chain, resolving any variable-length predecessors on demand.

---

## Cross-layer payload dispatch — `LayerMapping`

Protocols stack on top of each other through payload fields. `LayerMapping` maps a payload `RawField` to a concrete `Frame` type based on a type-discriminator field in the same frame:

```python
Ethernet_Payloads = LayerMapping(EthernetII.data).by(EthernetII.type, {
    0x0800: IPv4,
    0x86dd: IPv6,
})

IP_Payloads = LayerMapping(IPv4.Payload).by(IPv4.Protocol, {
    0x06: TCP,
    0x11: UDP,
})
```

Mappings are composed with `+` or merged via `base=` constructor argument. A `LayerMapping` is passed to `Frames.dissect(data, mappings=...)` so the dissector can resolve payload types automatically:

```python
pcap = PCAPFile.open_file(path, mappings=PCAP_Payloads + Ethernet_Payloads + IP_Payloads)
```

When a payload field is read (via `field.as_frame(frame)`), the backend walks its mapping table, reads the discriminator, and constructs the appropriate `Frame` subclass over the raw payload bytes.

---

## Protocol stack pipeline — `FrameStack`

For file or stream processing, `FrameStack` chains `StackLayer` instances into a receive pipeline. Each layer:

1. Receives a `StackState` (current data + context)
2. Decodes one frame
3. Yields one or more new `StackState` objects carrying the payload data and a `payload_type` key

```
FrameStack(PCAPLayer)
  └── FrameStack(EthernetLayer)
        └── FrameStack(IPLayer)
              ├── FrameStack(TCPLayer)    ← streaming
              └── FrameStack(UDPLayer)
```

Streaming layers (TCP) have a many-to-many relationship between transport segments and application frames. They maintain a `RawDataQueue` and only yield a `StackState` once a complete application-layer frame is available.

---

## Key data flow — dissection

```
RawData (bytes)
    │
    ▼
DissectorBackend(frame, mappings, data)
    │  field.get(frame)
    ▼
Field.decode_bit_length(...)   ← resolve length via Calculator chain
    │
    ▼
Field.decode(data[offset:], bit_length, backend)
    │                         │
    │   IntField               └── RawField / SubStructureField / LVField / Sequence
    ▼
IntegerCodec.decode(data)
```

All field reads are lazy; a field is decoded only when its value is first accessed. Decoded values are cached in `BackendImplementation.field_values`.

---

## Key data flow — encoding

```
ComposingBackend  (empty field_values dict)
    │  field.set(frame, value)
    ▼
field_values[field] = value
    │
    ▼  frame.encode()
FrameStructure.commit(frame)   ← runs all commit procedures (fills lengths, offsets, choices)
    │
    ▼
for field in structure.fields:
    Field.encode(value, state)  → RawData
    │
    ▼
Raw.sequence([...])  → final byte buffer
```

---

## Adding a new protocol

1. Create a file in `framing/frame_types/`.
2. Subclass `Frame`, instantiate `Structure['Name']()` as a class attribute.
3. Declare fields with `structure.integer(...)`, `structure.raw(...)`, `structure.sub(...)`.
4. Wire variable-length fields with `.length_by(ValueOf(...))` or `.end_offset_by(ValueOf(...) * n)`.
5. If the protocol has a payload, define a `LayerMapping` constant.
6. If the protocol sits on top of an existing one, add its mapping entry to that protocol's `LayerMapping`.

See `framing/frame_types/ethernet_frames.py` (simplest) and `framing/frame_types/dns_frames.py` (sequences, selections, cross-field paths) as reference implementations.
