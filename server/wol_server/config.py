from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .mailer import SmtpSettings

MIN_PEPPER_LENGTH = 32
LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR"}
SMTP_SECURITY_PORTS = {"ssl": 465, "starttls": 587, "none": 25}


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Settings:
    host: str
    client_port: int
    device_port: int
    cert_file: Path
    key_file: Path
    database_url: str
    pepper: bytes
    db_pool_size: int = 10
    log_level: str = "INFO"
    smtp: SmtpSettings | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str], base_dir: Path) -> Settings:
        def required(name: str) -> str:
            value = env.get(name, "").strip()
            if not value:
                raise ConfigError(f"{name} is not set")
            return value

        def port(name: str) -> int:
            raw = required(name)
            if not raw.isdigit() or not 0 < int(raw) < 65536:
                raise ConfigError(f"{name} must be a port number, got {raw!r}")
            return int(raw)

        def path(name: str, default: str) -> Path:
            resolved = (base_dir / env.get(name, default).strip()).resolve()
            if not resolved.is_file():
                raise ConfigError(f"{name}: file not found: {resolved}")
            return resolved

        pepper = required("TOKEN_PEPPER").encode()
        if len(pepper) < MIN_PEPPER_LENGTH:
            raise ConfigError(f"TOKEN_PEPPER must be at least {MIN_PEPPER_LENGTH} characters")

        client_port, device_port = port("CLIENT_PORT"), port("DEVICE_PORT")
        if client_port == device_port:
            raise ConfigError("CLIENT_PORT and DEVICE_PORT must differ")

        database_url = required("DATABASE_URL")
        if not database_url.startswith(("postgresql://", "postgres://")):
            raise ConfigError("DATABASE_URL must be a postgresql:// URL")

        pool_size = env.get("DB_POOL_SIZE", "10").strip()
        if not pool_size.isdigit() or not 1 <= int(pool_size) <= 100:
            raise ConfigError("DB_POOL_SIZE must be a number between 1 and 100")

        log_level = env.get("LOG_LEVEL", "INFO").strip().upper()
        if log_level not in LOG_LEVELS:
            raise ConfigError(f"LOG_LEVEL must be one of {sorted(LOG_LEVELS)}")

        return cls(
            host=env.get("SERVER_HOST", "0.0.0.0").strip(),
            client_port=client_port,
            device_port=device_port,
            cert_file=path("TLS_CERT_FILE", "server.crt"),
            key_file=path("TLS_KEY_FILE", "server.key"),
            database_url=database_url,
            pepper=pepper,
            db_pool_size=int(pool_size),
            log_level=log_level,
            smtp=smtp_settings(env),
        )


def smtp_settings(env: Mapping[str, str]) -> SmtpSettings | None:
    """SMTP is optional; without SMTP_HOST password reset is disabled."""
    host = env.get("SMTP_HOST", "").strip()
    if not host:
        return None

    security = env.get("SMTP_SECURITY", "starttls").strip().lower()
    if security not in SMTP_SECURITY_PORTS:
        raise ConfigError(f"SMTP_SECURITY must be one of {sorted(SMTP_SECURITY_PORTS)}")

    raw_port = env.get("SMTP_PORT", "").strip() or str(SMTP_SECURITY_PORTS[security])
    if not raw_port.isdigit() or not 0 < int(raw_port) < 65536:
        raise ConfigError(f"SMTP_PORT must be a port number, got {raw_port!r}")

    username = env.get("SMTP_USER", "").strip()
    password = env.get("SMTP_PASSWORD", "")
    if username and security == "none":
        raise ConfigError("refusing to send SMTP_PASSWORD without TLS; set SMTP_SECURITY")

    sender = env.get("SMTP_FROM", "").strip() or username
    if "@" not in sender:
        raise ConfigError("SMTP_FROM must be an e-mail address")

    return SmtpSettings(
        host=host,
        port=int(raw_port),
        security=security,
        username=username,
        password=password,
        sender=sender,
        sender_name=env.get("SMTP_FROM_NAME", "").strip() or "WoL Server",
    )
