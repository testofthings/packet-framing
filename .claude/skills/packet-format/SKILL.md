---
name: packet-frame-modeling
description: "Add or update a binary protocol frame model in packet-framing. Use when: adding a new protocol, adding a new packet type, extending an existing frame definition, adding a new field type, defining a payload mapping, supporting a new format in the layer stack. Covers Structure, Selection, Field, LayerMapping, StackLayer."
argument-hint: "Protocol or format to add or update (e.g. 'ICMP', 'HTTP/1.1 over TCP')"
---

# Adding or Updating a Packet Format

## When to Use

- Adding support for a new network protocol (e.g. ICMP, DHCP extension, QUIC)
- Adding a new packet type to an existing protocol (e.g. a new DNS resource record type)
- Extending an existing `Frame` subclass with new fields
- Defining a new `LayerMapping` or extending an existing one
- Adding a custom `StackLayer` for streaming or multi-frame protocols

## Reference Material

Read [documentation/Architecture.md](../../../documentation/Architecture.md) before starting — it explains `Structure`, `Selection`, `Field`, `Calculator`, `LayerMapping`, and the backend pattern.

To match the actual packet format it is ESSENTIAL to have traffic captures
in PCAP format to write unit tests using real data. Ask user to point out PCAP file
with the protocol traffic.

---

## Workflow

This is an iterative process. **Stop after each phase, show what was done, and wait for the user to review before continuing.**

```
Phase 1: Gather info + write frame model  →  user review
Phase 2: Write unit tests, run them       →  user review
Phase 3: Update documentation             →  user review
Phase 4 (optional): LayerMapping + StackLayer  →  user review
```

---

## Phase 1 — Frame model

### 1a. Gather information

Before writing any code, establish:

1. **Protocol name and RFC/specification reference** (add as a comment at the top of the file).
2. **Where in the stack it lives**: what carries it and what it carries.
3. **Field layout**: for each field — bit/byte width, fixed or variable-length, and the rule that resolves variable lengths.
4. **Discriminated unions**: does any field determine which of several alternative sub-structures is present? (→ `Selection`)
5. **Existing file to extend**: check `framing/frame_types/` for an existing file.

If the user has not provided a field table, ask for it or point to the RFC before writing any code.

### 1b. Choose the right file

| Situation | Action |
|---|---|
| New protocol | Create `framing/frame_types/<protocol>_frames.py` |
| New packet type inside existing protocol | Edit the existing `framing/frame_types/<protocol>_frames.py` |
| New payload mapping only | Edit the file that owns the lower-layer `LayerMapping` |

### 1c. Write the frame model

**Minimal fixed-field frame:**

```python
# https://www.ietf.org/rfc/rfcXXXX.txt

from framing.base import Frame
from framing.fields import Structure

class MyFrame(Frame):
    structure = Structure['MyFrame']()

    field_a = structure.integer(bits=8)
    field_b = structure.integer(bits=16)
    payload = structure.raw()
```

**Variable-length field driven by another field:**

```python
length  = structure.integer(bytes=2)
data    = structure.raw().length_by(ValueOf(length))        # byte count
options = structure.raw().end_offset_by(ValueOf(length))    # absolute end offset
# multiply when field is in different units, e.g. IHL is in 32-bit words:
# options = structure.raw().end_offset_by(ValueOf(ihl) * 4)
```

**Cross-frame field path (count field in a header sub-frame):**

```python
items = Sequence(structure.sub(Item)).count_by(
    HeaderFrame.Count.of(Header)   # Header is the SubStructureField in this frame
)
```

**Discriminated union (`Selection`):**

```python
class Payload(Frame):
    structure = Selection['Payload']()

    default_data = structure.raw()                           # fallback
    type_a       = structure.choice(1, structure.raw(bytes=4))
    type_b       = structure.choice(2, structure.sub(TypeBFrame))

# In the parent frame:
payload = structure.sub(Payload).choice_by(type_field).length_by(ValueOf(length_field))
```

**Length-Value (LV) field:**

```python
from framing.fields import LVField, RawField
from framing.codecs import IntegerFormat

data = structure.field(LVField(RawField(Raw.empty), IntegerFormat(bytes=1)))
```

**Sequence of sub-frames:**

```python
records = Sequence(structure.sub(RecordFrame)).count_by(ValueOf(count_field))
```

NOTE: Source code is quite compact, so inspect it to gain more insight.

### 1d. Stop and review

Show the user the new/changed frame class(es). Ask:
- Are the field names correct?
- Are any fields missing or wrong width?
- Do the length/offset rules look right?

**Do not proceed to Phase 2 until the user confirms the model.**

---

## Phase 2 — Unit tests

Create or extend `tests/<protocol>_test.py`.

Write one test function per packet type defined in Phase 1. Each test must:

1. **Decode a concrete byte sequence** and assert every field value:

```python
from framing.frames import Frames
from framing.raw_data import Raw
from framing.frame_types.my_frames import MyFrame

def test_my_frame_decode():
    data = Raw.hex("0001 0002 ...")
    f = MyFrame(Frames.dissect(data))
    assert MyFrame.field_a[f] == 0x00
    assert MyFrame.field_b[f] == 0x0001
    assert f.byte_length() == len(data)
```

2. **Parse captured traffic** (PCAP) and assert field values:

```python
def test_my_frame_decode():
   pcap = PCAPFile.open_file(
       pathlib.Path("samples/<file>pcap"),
       mappings=PCAP_Payloads + Ethernet_Payloads + IP_Payloads)

    # Parse frame <num> from UDP payload

    data = UDP.Data[PCAPFile.Packet_Records.item(pcap, <num>) /
        PacketRecord.Packet_Data / EthernetII.data / IPv4.Payload]
    msg = MyFrame(Frames.dissect(data))
    assert ...
```

3. **Round-trip encode** (compose → encode → dissect) and assert field values survive:

```python
def test_my_frame_encode():
    f = MyFrame(Frames.compose())
    MyFrame.field_a[f] = 42
    MyFrame.field_b[f] = 1024
    encoded = f.encode()
    f2 = MyFrame(Frames.dissect(encoded))
    assert MyFrame.field_a[f2] == 42
    assert MyFrame.field_b[f2] == 1024
```

Run the tests and fix any failures before continuing:

```
pytest tests/<protocol>_test.py -v
```

### Stop and review

Show the user the test output. Ask:
- Do the decoded values match the specification?
- Are there packet variants or edge cases not yet covered?

**Do not proceed to Phase 3 until all tests pass and the user confirms.**

---

## Phase 3 — Documentation

Update `documentation/Formats.md`: add a bullet for the new protocol, noting what variants are supported (e.g. "DNS over UDP and TCP, A/NS/CNAME/SOA/AAAA record types").

If a new file was created, add a one-line module docstring at the top describing what the file contains and its RFC reference.

If any `LayerMapping` constant was added in this phase, document it in the module docstring.

### Stop and review

Show the documentation changes. Ask whether the description is complete and accurate.

---

## Phase 4 (optional) — Layer mapping and streaming

Only proceed here if the user explicitly requests it after Phase 3.

### Layer mappings

If the new protocol **is carried** by an existing protocol, add it to that protocol's `LayerMapping`:

```python
from framing.frame_types.my_frames import MyFrame

UDP_Payloads = LayerMapping(UDP.Data).by(UDP.Destination_port, {
    1234: MyFrame,
})
```

If the new protocol **carries** other protocols, define its own `LayerMapping` constant and export it from the module.

Mappings compose with `+`:

```python
full_stack = PCAP_Payloads + Ethernet_Payloads + IP_Payloads + MyFrame_Payloads
```

### Streaming `StackLayer`

Only needed when the protocol is a streaming transport (splits application frames across segments).

```python
from framing.layer_stack import StackLayer, StackState

class MyStreamLayer(StackLayer):
    def __init__(self):
        super().__init__(MyFrame)
        self.streaming = True

    def receive(self, state: StackState):
        # buffer data, yield complete frames
        ...
```

Refer to `TLSRecordLayer` in `framing/frame_types/tls_frames.py` as the reference implementation.

After implementing, add integration tests (PCAP-based) before marking done.

---

## Common Pitfalls

| Symptom | Likely cause |
|---|---|
| `EOFError` reading a field | Data shorter than the frame declares — check length resolver |
| Field reads `0` unexpectedly | Offset accumulation wrong — verify preceding variable-length fields all have resolvers |
| `StructureError: No fields defined` | `Structure['Name']()` instantiated before any fields added |
| Wrong choice decoded for `Selection` | `choice_by(discriminator)` missing, or key mapping off-by-one |
| Encoding doesn't fill length field | Missing `.length_by(ValueOf(...))` or `.at_commit(...)` |
| `ValueError: Field not found in frame or its parents` | `FieldPath` traversal (`X.of(field)`) crosses frame boundaries incorrectly |

## Reference Implementations

| Complexity | File |
|---|---|
| Minimal fixed-length | `framing/frame_types/ethernet_frames.py` |
| Variable-length fields | `framing/frame_types/ipv4_frames.py` |
| Flag enums | `framing/frame_types/tcp_frames.py` |
| Sequences + cross-frame paths | `framing/frame_types/dns_frames.py` |
| Selection (discriminated union) | `framing/frame_types/tls_frames.py` |
| Streaming StackLayer | `framing/frame_types/tls_frames.py` (`TLSRecordLayer`) |
