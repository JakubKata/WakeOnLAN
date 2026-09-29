from .protocol import Err


class CommandError(Exception):
    """Aborts the current command; the peer receives ``NACK [code]``."""

    def __init__(self, code: Err):
        super().__init__(code)
        self.code = code
