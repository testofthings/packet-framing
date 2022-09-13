from framing.base import Frame, S, FrameBackend
from framing.backends import EditableBackend


class BaseFrame(Frame[S]):
    def __init__(self, backend: FrameBackend = None):
        super().__init__(backend or EditableBackend(self))


