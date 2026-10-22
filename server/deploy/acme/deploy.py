"""Certbot deploy hook: publish only this service's TLS identity, atomically."""
from __future__ import annotations

import os
import ssl
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.verification import PolicyBuilder, Store

RUNTIME_DIR = Path("/run/wol-tls")
SERVER_UID = 10001


def publish(
    lineage: Path, destination: Path, server_name: str,
    *, _trust_roots: list[x509.Certificate] | None = None,
) -> None:
    chain_path, key_path = lineage / "fullchain.pem", lineage / "privkey.pem"
    chain = chain_path.read_bytes()
    key = key_path.read_bytes()
    certs = x509.load_pem_x509_certificates(chain)
    if not certs:
        raise ValueError("ACME returned no certificates")
    now = datetime.now(timezone.utc)
    if any(not cert.not_valid_before_utc <= now < cert.not_valid_after_utc for cert in certs):
        raise ValueError("ACME certificate chain is not currently valid")
    names = certs[0].extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if server_name.lower() not in {name.lower() for name in names.get_values_for_type(x509.DNSName)}:
        raise ValueError("ACME certificate does not match TLS_SERVER_NAME")
    roots = _trust_roots
    if roots is None:
        roots = [
            x509.load_der_x509_certificate(certificate)
            for certificate in ssl.create_default_context().get_ca_certs(binary_form=True)
        ]
    verifier = PolicyBuilder().store(Store(roots)).time(now).build_server_verifier(
        x509.DNSName(server_name.lower())
    )
    verifier.verify(certs[0], certs[1:])

    # Validate the bytes being published, not another generation of ACME symlinks.
    destination.parent.mkdir(parents=True, exist_ok=True)
    # renew.sh uses umask 077; the unprivileged server still needs traversal.
    destination.parent.chmod(0o755)
    identity = chain.rstrip() + b"\n" + key.rstrip() + b"\n"
    descriptor, temporary_name = tempfile.mkstemp(prefix=".identity-", dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(identity)
            output.flush()
            os.fchmod(output.fileno(), 0o400)
            os.fchown(output.fileno(), SERVER_UID, SERVER_UID)
            os.fsync(output.fileno())
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(temporary, password=lambda: b"")
        if destination.exists() and destination.read_bytes() == identity:
            current = destination.stat()
            if current.st_uid == SERVER_UID and current.st_mode & 0o777 == 0o400:
                return
        os.replace(temporary, destination)
        directory_fd = os.open(destination.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    publish(
        Path(os.environ["RENEWED_LINEAGE"]),
        RUNTIME_DIR / "server.pem",
        os.environ["TLS_SERVER_NAME"],
    )
