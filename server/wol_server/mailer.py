"""Outgoing e-mail over SMTP. Sending runs in the background so replies never wait on it."""

from __future__ import annotations

import asyncio
import logging
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

log = logging.getLogger(__name__)

SMTP_TIMEOUT = 20


@dataclass(frozen=True)
class SmtpSettings:
    host: str
    port: int
    security: str  # "ssl", "starttls" or "none"
    username: str
    password: str
    sender: str
    sender_name: str = "WoL Server"


class Mailer:
    def __init__(self, settings: SmtpSettings):
        self._settings = settings
        self._tasks: set[asyncio.Task[None]] = set()

    def send_later(self, to: str, subject: str, body: str) -> None:
        """Queue a message; failures are logged, never reported to the requester."""
        task = asyncio.create_task(self._send(to, subject, body))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def close(self) -> None:
        if self._tasks:
            await asyncio.wait(self._tasks, timeout=SMTP_TIMEOUT)

    async def _send(self, to: str, subject: str, body: str) -> None:
        message = EmailMessage()
        message["From"] = formataddr((self._settings.sender_name, self._settings.sender))
        message["To"] = to
        message["Subject"] = subject
        message["Message-ID"] = make_msgid(domain=self._settings.sender.rpartition("@")[2] or None)
        message.set_content(body)
        try:
            await asyncio.to_thread(self._deliver, message)
        except (OSError, smtplib.SMTPException) as exc:
            log.error("sending mail to %s failed: %r", to, exc)

    def _deliver(self, message: EmailMessage) -> None:
        s = self._settings
        context = ssl.create_default_context()
        if s.security == "ssl":
            smtp: smtplib.SMTP = smtplib.SMTP_SSL(s.host, s.port, timeout=SMTP_TIMEOUT, context=context)
        else:
            smtp = smtplib.SMTP(s.host, s.port, timeout=SMTP_TIMEOUT)
        with smtp:
            if s.security == "starttls":
                smtp.starttls(context=context)
            if s.username:
                smtp.login(s.username, s.password)
            smtp.send_message(message)
