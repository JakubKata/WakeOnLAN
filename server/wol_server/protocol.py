"""Wire format: one JSON object per line, ``{"COMMAND": [arg, ...]}``."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum

MAX_LINE_BYTES = 4096


class Cmd(StrEnum):
    ACK = "ACK"
    NACK = "NACK"
    PING = "PING"
    PONG = "PONG"

    REGISTER = "REGISTER"
    LOGIN = "LOGIN"
    RESUME = "RESUME"
    REQUEST_PASSWORD_RESET = "REQUEST_PASSWORD_RESET"
    RESET_PASSWORD = "RESET_PASSWORD"
    LOGOUT = "LOGOUT"
    LOGOUT_ALL = "LOGOUT_ALL"
    CHANGE_PASSWORD = "CHANGE_PASSWORD"
    CHANGE_NAME = "CHANGE_NAME"
    DELETE_ACCOUNT = "DELETE_ACCOUNT"

    CREATE_CLAIM = "CREATE_CLAIM"
    LIST_DEVICES = "LIST_DEVICES"
    RENAME_DEVICE = "RENAME_DEVICE"
    REMOVE_DEVICE = "REMOVE_DEVICE"
    ROTATE_DEVICE_SECRET = "ROTATE_DEVICE_SECRET"

    ADD_TARGET = "ADD_TARGET"
    LIST_TARGETS = "LIST_TARGETS"
    RENAME_TARGET = "RENAME_TARGET"
    ASSIGN_TARGET = "ASSIGN_TARGET"
    REMOVE_TARGET = "REMOVE_TARGET"
    WAKE_UP = "WAKE_UP"

    DEVICE_CLAIM = "DEVICE_CLAIM"
    DEVICE_AUTH = "DEVICE_AUTH"
    WAKE_ACK = "WAKE_ACK"
    SECRET_ACK = "SECRET_ACK"
    SET_SECRET = "SET_SECRET"
    UNPAIRED = "UNPAIRED"


class Err(StrEnum):
    BAD_FRAME = "bad_frame"
    FRAME_TOO_LONG = "frame_too_long"
    UNKNOWN_COMMAND = "unknown_command"
    BAD_ARGS = "bad_args"
    UNAUTHENTICATED = "unauthenticated"
    ALREADY_AUTHENTICATED = "already_authenticated"
    RATE_LIMITED = "rate_limited"
    INVALID_CREDENTIALS = "invalid_credentials"
    INVALID_TOKEN = "invalid_token"
    INVALID_NAME = "invalid_name"
    INVALID_EMAIL = "invalid_email"
    INVALID_LABEL = "invalid_label"
    INVALID_MAC = "invalid_mac"
    WEAK_PASSWORD = "weak_password"
    ACCOUNT_EXISTS = "account_exists"
    NAME_TAKEN = "name_taken"
    NOT_FOUND = "not_found"
    DUPLICATE = "duplicate"
    LIMIT_REACHED = "limit_reached"
    NO_DEVICE = "no_device"
    DEVICE_OFFLINE = "device_offline"
    DEVICE_UNREACHABLE = "device_unreachable"
    RESET_UNAVAILABLE = "reset_unavailable"
    INTERNAL = "internal"


class ProtocolError(Exception):
    """The received line is not a valid message."""


@dataclass(frozen=True, slots=True)
class Message:
    command: str
    args: tuple[object, ...] = ()

    def encode(self) -> bytes:
        payload = {str(self.command): list(self.args)}
        return json.dumps(payload, separators=(",", ":")).encode() + b"\n"

    @classmethod
    def decode(cls, line: bytes) -> Message:
        try:
            data = json.loads(line)
        except (ValueError, RecursionError) as exc:
            raise ProtocolError("invalid JSON") from exc
        if not isinstance(data, dict) or len(data) != 1:
            raise ProtocolError("expected a single-key object")
        ((command, args),) = data.items()
        if not isinstance(args, list):
            raise ProtocolError("arguments must be an array")
        return cls(command, tuple(args))


def ack(*args: object) -> Message:
    return Message(Cmd.ACK, args)


def nack(code: Err) -> Message:
    return Message(Cmd.NACK, (str(code),))
