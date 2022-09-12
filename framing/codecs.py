class IntegerCodec:
    """Base class for integer codecs"""
    pass


class IntegerCodecs:
    """Codec factory"""

    @classmethod
    def bits(cls, bits: int) -> IntegerCodec:
        return IntegerCodec()



