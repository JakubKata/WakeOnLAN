from __future__ import annotations

import logging
import ssl
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from .config import Settings

log = logging.getLogger(__name__)
EXPIRY_WARNING = timedelta(days=14)


def _signature(paths: tuple[Path, Path]) -> tuple[tuple[int, ...], ...]:
    return tuple(
        (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
        for stat in (path.stat() for path in paths)
    )


class CertificateError(ssl.SSLError):
    """A replacement TLS identity must never replace a working one on failure."""


class ReloadableTLS:
    """Build a fresh context, then swap it; established TLS streams keep their context."""

    def __init__(self, settings: Settings, *, _trust_roots: list[x509.Certificate] | None = None):
        self._paths = (settings.cert_file, settings.key_file)
        self._server_name = settings.tls_server_name
        # Internal injection for isolated CA tests; production always uses the
        # platform trust store and has no setting to disable path verification.
        self._trust_roots = _trust_roots
        self._loaded_signature: tuple[tuple[int, ...], ...] | None = None
        self._last_warning: date | None = None
        self.context: ssl.SSLContext
        self.expires_at: datetime
        self._load()

    def _load(self) -> None:
        before = _signature(self._paths)
        cert_file, key_file = self._paths
        try:
            chain = x509.load_pem_x509_certificates(cert_file.read_bytes())
            if not chain:
                raise ValueError("empty certificate chain")
        except ValueError as exc:
            raise CertificateError("invalid TLS certificate chain") from exc

        now = datetime.now(timezone.utc)
        for certificate in chain:
            if not certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc:
                raise CertificateError("TLS certificate chain is expired or not yet valid")
        leaf = chain[0]
        try:
            usage = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except x509.ExtensionNotFound:
            pass
        else:
            if ExtendedKeyUsageOID.SERVER_AUTH not in usage:
                raise CertificateError("TLS certificate is not valid for server authentication")
        if self._server_name:
            try:
                names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            except x509.ExtensionNotFound as exc:
                raise CertificateError("TLS certificate has no DNS subject alternative name") from exc
            if self._server_name not in {name.lower() for name in names.get_values_for_type(x509.DNSName)}:
                raise CertificateError("TLS certificate does not contain TLS_SERVER_NAME")
            roots = self._trust_roots
            if roots is None:
                roots = [
                    x509.load_der_x509_certificate(certificate)
                    for certificate in ssl.create_default_context().get_ca_certs(binary_form=True)
                ]
            try:
                verifier = PolicyBuilder().store(Store(roots)).time(now).build_server_verifier(
                    x509.DNSName(self._server_name)
                )
                verifier.verify(leaf, chain[1:])
            except (ValueError, VerificationError) as exc:
                raise CertificateError("TLS certificate has no valid chain to a trusted CA") from exc

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.options |= ssl.OP_NO_COMPRESSION
        # An encrypted key is a deployment error, never an interactive password prompt.
        context.load_cert_chain(certfile=cert_file, keyfile=key_file, password=lambda: b"")
        if _signature(self._paths) != before:
            raise CertificateError("TLS files changed while loading; retrying on the next check")

        self.context = context
        self.expires_at = min(cert.not_valid_after_utc for cert in chain)
        self._loaded_signature = before
        self._last_warning = None
        log.info("TLS certificate loaded; chain expires at %s", self.expires_at.isoformat())
        self._warn_if_expiring()

    def reload_if_changed(self) -> bool:
        try:
            if _signature(self._paths) != self._loaded_signature:
                self._load()
                return True
        except Exception:
            # A malformed replacement (including unsupported X.509 extensions)
            # must not terminate the watcher or alter the active TLS identity.
            log.exception("TLS certificate reload failed; keeping the previous TLS context")
        self._warn_if_expiring()
        return False

    def _warn_if_expiring(self) -> None:
        now = datetime.now(timezone.utc)
        if self.expires_at - now <= EXPIRY_WARNING and self._last_warning != now.date():
            log.error("TLS certificate expires at %s; check ACME renewal immediately", self.expires_at.isoformat())
            self._last_warning = now.date()
