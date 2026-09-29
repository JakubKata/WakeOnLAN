from __future__ import annotations

import asyncio
import contextlib

from .protocol import Message

SEND_TIMEOUT = 10.0
CLOSE_TIMEOUT = 5.0


class FrameTooLong(Exception):
    """The peer sent a line longer than the stream limit."""


class Connection:
    """A TLS stream carrying newline-delimited messages."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self._reader = reader
        self._writer = writer
        peer = writer.get_extra_info("peername")
        self.peer: str = peer[0] if peer else "unknown"

    @property
    def closed(self) -> bool:
        return self._writer.is_closing()

    async def read_message(self, timeout: float) -> Message | None:
        """Return the next message, or None when the peer closed the stream.

        Raises TimeoutError, FrameTooLong or ProtocolError.
        """
        try:
            line = await asyncio.wait_for(self._reader.readline(), timeout)
        except ValueError as exc:
            raise FrameTooLong from exc
        if not line.endswith(b"\n"):
            return None
        return Message.decode(line)

    async def send(self, message: Message) -> None:
        if self.closed:
            raise ConnectionResetError("connection is closed")
        self._writer.write(message.encode())
        await asyncio.wait_for(self._writer.drain(), SEND_TIMEOUT)

    def close(self) -> None:
        self._writer.close()

    async def wait_closed(self) -> None:
        with contextlib.suppress(Exception):
            await asyncio.wait_for(self._writer.wait_closed(), CLOSE_TIMEOUT)
