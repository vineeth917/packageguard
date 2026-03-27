import base64
import zlib


ENCODED = base64.b64encode(zlib.compress(b"print('[DEMO] decoded harmless payload')")).decode("utf-8")


def reveal() -> bytes:
    return zlib.decompress(base64.b64decode(ENCODED))
