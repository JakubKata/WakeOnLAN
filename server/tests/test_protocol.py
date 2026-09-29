import asyncio

import pytest

from wol_server.protocol import MAX_LINE_BYTES, Cmd, Message, ProtocolError, ack, nack, Err
from wol_server.transport import Connection, FrameTooLong


class StubWriter:
    def get_extra_info(self, name):
        return ("192.0.2.1", 1234) if name == "peername" else None

    def is_closing(self):
        return False


def connection_with(*chunks: bytes, eof: bool = True) -> Connection:
    reader = asyncio.StreamReader(limit=MAX_LINE_BYTES)
    for chunk in chunks:
        reader.feed_data(chunk)
    if eof:
        reader.feed_eof()
    return Connection(reader, StubWriter())


def test_roundtrip():
    message = Message(Cmd.WAKE_UP, ("abc", 3, {"k": "v"}))
    assert Message.decode(message.encode()) == Message("WAKE_UP", ("abc", 3, {"k": "v"}))


def test_encode_is_single_ascii_line():
    data = Message("X", ("zażółć\n",)).encode()
    assert data.endswith(b"\n") and data.count(b"\n") == 1
    assert data.isascii()


def test_ack_and_nack():
    assert ack(1, "a") == Message("ACK", (1, "a"))
    assert nack(Err.BAD_ARGS) == Message("NACK", ("bad_args",))


@pytest.mark.parametrize(
    "line",
    [b"not json\n", b"[]\n", b'{"A":[],"B":[]}\n', b'{"A":"x"}\n', b"\xff\xfe\n", b"[" * 5000 + b"\n"],
)
def test_decode_rejects_malformed(line):
    with pytest.raises(ProtocolError):
        Message.decode(line)


def test_two_messages_in_one_chunk():
    async def scenario():
        conn = connection_with(b'{"A":[1]}\n{"B":[2]}\n')
        assert await conn.read_message(1) == Message("A", (1,))
        assert await conn.read_message(1) == Message("B", (2,))
        assert await conn.read_message(1) is None

    asyncio.run(scenario())


def test_message_split_across_chunks():
    async def scenario():
        conn = connection_with(b'{"A":', b'["x"]', b"}\n")
        assert await conn.read_message(1) == Message("A", ("x",))

    asyncio.run(scenario())


def test_eof_mid_line_is_treated_as_close():
    async def scenario():
        conn = connection_with(b'{"A":[')
        assert await conn.read_message(1) is None

    asyncio.run(scenario())


def test_oversized_line():
    async def scenario():
        conn = connection_with(b"x" * (MAX_LINE_BYTES + 10) + b"\n")
        with pytest.raises(FrameTooLong):
            await conn.read_message(1)

    asyncio.run(scenario())


def test_read_timeout_keeps_partial_data():
    async def scenario():
        reader = asyncio.StreamReader(limit=MAX_LINE_BYTES)
        conn = Connection(reader, StubWriter())
        reader.feed_data(b'{"A":')
        with pytest.raises(TimeoutError):
            await conn.read_message(0.05)
        reader.feed_data(b"[]}\n")
        assert await conn.read_message(1) == Message("A", ())

    asyncio.run(scenario())
