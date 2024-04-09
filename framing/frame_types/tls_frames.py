from typing import Iterable
from framing.base import Frame, LayerMapping
from framing.data_queue import RawDataQueue
from framing.fields import Selection, Structure, ValueOf
from framing.frame_processors import Processor
from framing.frames import Frames
from framing.layer_stack import StackLayer, StackState


class ClientHello(Frame):
    structure = Structure['ClientHello']()

    version = structure.integer(bytes=2)
    random = structure.raw(bytes=32)
    session_id_length = structure.integer(bytes=1)
    session_id = structure.raw().length_by(session_id_length)
    cipher_suites_length = structure.integer(bytes=2)
    cipher_suites = structure.raw().length_by(cipher_suites_length)
    compression_methods_length = structure.integer(bytes=1)
    compression_methods = structure.raw().length_by(compression_methods_length)
    extensions_length = structure.integer(bytes=2)
    extensions = structure.raw().length_by(extensions_length)


class ServerHello(Frame):
    structure = Structure['ServerHello']()

    version = structure.integer(bytes=2)
    random = structure.raw(bytes=32)
    session_id_length = structure.integer(bytes=1)
    session_id = structure.raw().length_by(session_id_length)
    cipher_suite = structure.integer(bytes=2)
    compression_method = structure.integer(bytes=1)
    extensions_length = structure.integer(bytes=2)
    extensions = structure.raw().length_by(extensions_length)

class TLSHandshakeMessage(Frame):
    structure = Selection['TLSHandshakeMessage']()

    client_hello = structure.choice(1, structure.sub(ClientHello))
    server_hello = structure.choice(2, structure.sub(ServerHello))


class TLSRecord(Frame):
    structure = Structure['TLSRecord']()

    ContentType = structure.integer(bits=8)
    ProtocolVersion = structure.integer(bits=16)
    length = structure.integer(bits=16)
    fragment = structure.raw().length_by(ValueOf(length))


class TLSHandshake(Frame):
    structure = Structure['TLSHandshake']()

    HandshakeType = structure.integer(bits=8)
    length = structure.integer(bits=24)
    message = structure.sub(TLSHandshakeMessage).length_by(ValueOf(length)).choice_by(HandshakeType)


class TLSChangeCipherSpec(Frame):
    structure = Structure['TLSChangeCipherSpec']()

    message = structure.integer(bits=8)


class TLSAlert(Frame):
    structure = Structure['TLSAlert']()

    level = structure.integer(bits=8)
    description = structure.integer(bits=8)


class TLSApplicationData(Frame):
    structure = Structure['TLSApplicationData']()

    data = structure.raw()


# TLS record content mappings
TLSRecord_Payloads = LayerMapping(TLSRecord.fragment).by(TLSRecord.ContentType, {
    22: TLSHandshake,
    20: TLSChangeCipherSpec,
    21: TLSAlert,
    23: TLSApplicationData,
})


class TLSRecordLayer(StackLayer):
    def __init__(self):
        super().__init__(TLSRecord)
        self.queue = RawDataQueue()

    def receive(self, state: StackState) -> Iterable[StackState]:
        record = TLSRecord(Frames.dissect(state.data))
        self.queue.push(TLSRecord.fragment[record])
        if not self.queue:
            return []
        data = self.queue.pull_all()
        return [state.add(record, TLSRecord.ContentType[record], data)]
