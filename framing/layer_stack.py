import re
from framing.backends import RawFrame
from framing.base import Frame
from framing.frames import Frames
from framing.raw_data import Raw, RawData


from typing import Any, Callable, Dict, Iterable, Optional, Tuple, Type


class StackState:
    """Extractor output, frame and way to get payload data"""
    def __init__(self, data: RawData, payload_type: Any = None, frame: Optional[Frame] = None, lower: Optional['StackState'] = None,
                 stream_id: Optional[Any] = None):
        self.data = data
        self.payload_type = payload_type
        self.frame = frame
        self.lower = lower
        self.stream_id = stream_id  # for streaming layers

    def add(self, frame: Frame, payload_type: Any = None, data: RawData = Raw.empty, stream_id: Optional[Any] = None):
        """Add frame to the stack"""
        self.frame = frame  # update this frame
        return StackState(data, payload_type, lower=self, stream_id=stream_id)

    def get_frame(self) -> Frame:
        """Get the top frame, look for it"""
        return self.frame or (self.lower.get_frame() if self.lower else None)

    def get_layer_names(self) -> str:
        """Get the string of layers names"""
        ls = []
        s = self
        while s:
            lower = s.lower
            if s.frame:
                fs = s.frame.structure.structure_name
                p = s.payload_type
                if isinstance(p, Tuple) and len(p) == 4:
                    # Assuming source address+port and destination address+port
                    ks = f"{p[0].as_ip_address()}.{p[1]}, {p[2].as_ip_address()}.{p[3]}"
                    fs = f"{ks}={fs}"
                elif p is not None:
                    fs = f"{p}={fs}"
                ls.insert(0, fs)
            s = lower
        return " / ".join(ls)

    def __repr__(self) -> str:
        s = self.get_layer_names()
        if self.payload_type is not None:
            s = f"{s} " if s else ""
            s += f"paylod={self.payload_type}"
        s = f"{s}\n" if s else ""
        s += f"{self.data}"
        return s


class FrameStackLayer:
    """Frame stack layer"""
    def __init__(self, frame_type: Type[Frame] = RawFrame):
        self.frame_type = frame_type
        self.streaming = False  # streaming layer? (e.g. TCP)
        # force frame type initialization
        frame_type(Frames.compose())

    def get_frame_type(self, state: StackState) -> Frame:
        """Get frame type, may depend on transport layer"""
        return self.frame_type

    def receive(self, state: StackState) -> Iterable[StackState]:
        """Receive data through the stack"""
        frame = RawFrame(Frames.dissect(state.data))
        return [state.add(frame)]

    def commit_read(self, stream_id: Any, byte_length: int):
        """Commit read of bytes from underlying stream"""
        pass

    def configure(self, spec: Dict[Any, Any]) -> 'FrameStackLayer':
        """Configure this layer"""
        return self

    def __repr__(self) -> str:
        return f"{self.frame_type.structure.structure_name}"


class StackLayerBuilder:
    """Stack layer builder"""
    def __init__(self, mappings: Dict[Any, Callable[[], FrameStackLayer]] = {}):
        self.mappings = mappings

    def build(self, transport: Type[Frame]) -> Dict[Any, FrameStackLayer]:
        """Get the layer key to layer mapping"""
        return {k: v() for k, v in self.mappings.items()}


class FrameStack:
    """Frame stack comprising layers"""
    def __init__(self, layer: FrameStackLayer = FrameStackLayer()):
        self.layer = layer
        self.next: Dict[Any, FrameStack] = {}  # higher layers keyed by payload types

    def receive(self, state: StackState) -> Iterable[StackState]:
        """Receive data through the stack"""
        if not self.next:
            # this is the top layer, no further processing
            frame_type = self.layer.get_frame_type(state)
            out_frame = frame_type(Frames.dissect(state.data))
            yield state.add(out_frame)
            return

        layer_receive = self.layer.receive(state)
        if self.layer.streaming:
            # stream data m-to-n relation between transports and payload frames
            for s in layer_receive:
                if not s.data:
                    continue  # no data to stream
                assert s.stream_id, "Expected stream ID for streaming layer"
                next = self.next.get(s.payload_type) or RawStackLayer()
                if next is None:
                    continue  # skip this payload type
                next_receive = list(next.receive(s))  # next level payloads
                try:
                    payload_len = s.frame.byte_length()  # this raises exception, if partial payload(s)
                    self.layer.commit_read(s.stream_id, payload_len)
                    yield from next_receive
                except EOFError as e:
                    pass  # leave data to stream
        else:
            # block transport, 1-to-n relation between transport and payload frames
            for s in layer_receive:
                next = self.next.get(s.payload_type) or RawStackLayer()
                if next is None:
                    continue  # skip this payload type
                next_receive = next.receive(s)
                yield from next_receive


    def build(self, spec: Dict[Any, Any], builder_map: Dict[str, StackLayerBuilder]):
        """Build this extractor recursively"""
        transport = self.layer.frame_type

        p_regexp = re.compile(r"^_(\d+)$")  # '_'+number for decimal protocol type
        x_regexp = re.compile(r"^_x([0-9a-fA-F]+)$") # '_x' for hexadecimal protocol type
        for k, v in spec.items():
            # specify sub-protocol?
            if not isinstance(v, Dict):
                continue  # no configuration
            if k == "raw":
                # show raw data
                layer = RawStackLayer()
                layer.configure(v)
                self.next[None] = FrameStack(layer)
                continue

            layer_builder = builder_map.get(k)
            if layer_builder is None:
                # not a protocol, maybe port number, payload type, etc. protocol key
                p_num = p_regexp.match(k) # integer key?
                key = int(p_num.group(1)) if p_num else None
                if key is None:
                    p_num = x_regexp.match(k)  # hex key?
                    key = int(p_num.group(1), 16) if p_num else None
                if key is None:
                    continue  # not key like for sub-protocol

                # payload protocol specified explictly
                proto_name = v.get('protocol') or v.get('p')
                if not proto_name:
                    raise ValueError('Missing protocol, use "protocol=" or "p="')
                layer_builder = builder_map.get(proto_name)
                if layer_builder is None:
                    raise ValueError(f'Unknown protocol "{proto_name}"')
                mappings = layer_builder.build(transport)
                if not mappings:
                    raise ValueError(f'Must specify layer key for "{proto_name}"')
                if len(mappings) != 1:
                    raise ValueError(f'"{proto_name}" is many protocols, it cannot be mapped to single layer key')
                layer_type = list(mappings.values())[0]
                layer = layer_type.configure(v)
                layer = layer.configure(v)
                s_layer = FrameStack(layer)
                s_layer.build(v, builder_map)
                self.next[key] = s_layer
            else:
                # key is protocol builder, may map to several protocols
                mappings = layer_builder.build(transport)
                for key, layer_type in mappings.items():
                    layer = layer_type.configure(v)
                    s_layer = FrameStack(layer)
                    s_layer.build(v, builder_map)
                    self.next[key] = s_layer

    def __repr__(self) -> str:
        s = f"{self.layer}"
        for k, v in self.next.items():
            s += f"\n  {k}: {v.layer}"
        return s


class RawStackLayer(FrameStackLayer):
    """Raw frame stack layer"""
    def __init__(self):
        super().__init__(RawFrame)

    def configure(self, spec: Dict[Any, Any]) -> FrameStackLayer:
        length = int(spec.get("len", -1))
        if length > 0:
            self.frame_type = RawFrame.build_with_lengths(min_bytes=1, bytes=length)
        return super().configure(spec)


