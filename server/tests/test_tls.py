"""Certificate lifecycle tests use real keys and TLS handshakes, never production ACME."""
from __future__ import annotations

import asyncio
import importlib.util
import os
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import trustme
from cryptography.x509.verification import VerificationError

from helpers import Peer, issue_webpki_cert, offline_services, trusted_roots
from wol_server.app import WolServer
from wol_server.config import Settings
from wol_server.handlers import build_dispatcher
from wol_server.protocol import Cmd, Err, nack
from wol_server.session import Role
from wol_server.tls import CertificateError, ReloadableTLS


def write_identity(directory: Path, cert: trustme.LeafCert) -> tuple[Path, Path]:
    directory.mkdir(exist_ok=True)
    cert_path, key_path = directory / "fullchain.pem", directory / "privkey.pem"
    cert_path.write_bytes(b"".join(pem.bytes() for pem in cert.cert_chain_pems))
    key_path.write_bytes(cert.private_key_pem.bytes())
    return cert_path, key_path


def settings_for(cert_path: Path, key_path: Path) -> Settings:
    return Settings(
        host="127.0.0.1", client_port=0, device_port=0,
        cert_file=cert_path, key_file=key_path,
        database_url="postgresql://unused", pepper=b"x" * 32,
        tls_server_name="localhost", tls_reload_interval=0.05,
    )


def peer_certificate(peer: Peer) -> bytes:
    return peer.writer.get_extra_info("ssl_object").getpeercert(binary_form=True)


def test_automatic_rotation_preserves_open_streams_and_serves_new_identity(tmp_path, monkeypatch):
    async def scenario():
        ca = trustme.CA()
        first, second = issue_webpki_cert(ca, "localhost"), issue_webpki_cert(ca, "localhost")
        settings = settings_for(*write_identity(tmp_path, first))
        monkeypatch.setattr(
            "wol_server.app.ReloadableTLS",
            lambda settings: ReloadableTLS(settings, _trust_roots=trusted_roots(ca)),
        )
        client_context = ssl.create_default_context()
        ca.configure_trust(client_context)
        peers = []
        async with offline_services() as services:
            server = WolServer(settings, services, build_dispatcher())
            await server.start()

            async def connect(role=Role.CLIENT):
                reader, writer = await asyncio.open_connection(
                    "127.0.0.1", server.port(role), ssl=client_context, server_hostname="localhost"
                )
                peer = Peer(reader, writer)
                peers.append(peer)
                return peer

            try:
                old = await connect()
                old_cert = peer_certificate(old)
                previous_context = server._tls.context
                write_identity(tmp_path, second)
                async with asyncio.timeout(3):
                    while server._tls.context is previous_context:
                        await asyncio.sleep(0.01)

                for role in Role:
                    new = await connect(role)
                    assert peer_certificate(new) != old_cert
                    assert peer_certificate(new) == ssl.PEM_cert_to_DER_cert(second.cert_chain_pems[0].bytes().decode())
                assert await old.call(Cmd.LIST_TARGETS) == nack(Err.UNAUTHENTICATED)
                assert peer_certificate(old) == old_cert

                # A broken deployment cannot poison even newly accepted connections.
                settings.cert_file.write_text("broken replacement")
                assert not server._tls.reload_if_changed()
                recovered = await connect()
                assert peer_certificate(recovered) == peer_certificate(new)
                assert await old.call(Cmd.LIST_TARGETS) == nack(Err.UNAUTHENTICATED)
            finally:
                for peer in peers:
                    await peer.close()
                await server.close()

    asyncio.run(scenario())


@pytest.mark.parametrize("replacement", [
    "expired", "future", "wrong_name", "mismatch", "malformed", "missing",
    "missing_intermediate", "unrelated_intermediate", "untrusted_root",
])
def test_invalid_replacement_keeps_previous_context_and_can_recover(tmp_path, replacement):
    ca = trustme.CA()
    original = issue_webpki_cert(ca, "localhost")
    settings = settings_for(*write_identity(tmp_path, original))
    tls = ReloadableTLS(settings, _trust_roots=trusted_roots(ca))
    context, expiry = tls.context, tls.expires_at
    now = datetime.now(timezone.utc)
    if replacement == "expired":
        write_identity(tmp_path, issue_webpki_cert(ca, "localhost", not_before=now - timedelta(days=2), not_after=now - timedelta(days=1)))
    elif replacement == "future":
        write_identity(tmp_path, issue_webpki_cert(ca, "localhost", not_before=now + timedelta(days=1)))
    elif replacement == "wrong_name":
        write_identity(tmp_path, issue_webpki_cert(ca, "other.example.com"))
    elif replacement == "mismatch":
        settings.key_file.write_bytes(issue_webpki_cert(ca, "localhost").private_key_pem.bytes())
    elif replacement == "malformed":
        settings.cert_file.write_text("not a certificate")
    elif replacement == "missing":
        settings.key_file.unlink()
    elif replacement == "untrusted_root":
        write_identity(tmp_path, issue_webpki_cert(trustme.CA(), "localhost"))
    else:
        intermediate = ca.create_child_ca()
        replacement_cert = issue_webpki_cert(intermediate, "localhost")
        write_identity(tmp_path, replacement_cert)
        chain = replacement_cert.cert_chain_pems[0].bytes()
        if replacement == "unrelated_intermediate":
            chain += ca.create_child_ca().cert_pem.bytes()
        settings.cert_file.write_bytes(chain)
    assert not tls.reload_if_changed()
    assert tls.context is context
    assert tls.expires_at == expiry

    write_identity(tmp_path, issue_webpki_cert(ca, "localhost"))
    assert tls.reload_if_changed()
    assert tls.context is not context
    assert not tls.reload_if_changed()


def test_invalid_initial_certificate_fails_closed(tmp_path):
    ca = trustme.CA()
    now = datetime.now(timezone.utc)
    expired = issue_webpki_cert(ca, "localhost", not_before=now - timedelta(days=2), not_after=now - timedelta(days=1))
    with pytest.raises(CertificateError, match="expired"):
        ReloadableTLS(settings_for(*write_identity(tmp_path, expired)), _trust_roots=trusted_roots(ca))


def test_production_initial_identity_requires_a_platform_trusted_chain(tmp_path):
    cert = issue_webpki_cert(trustme.CA(), "localhost")
    settings = settings_for(*write_identity(tmp_path, cert))
    with pytest.raises(CertificateError, match="trusted CA"):
        ReloadableTLS(settings)


def test_certificate_changed_during_load_is_not_published(tmp_path, monkeypatch):
    ca = trustme.CA()
    settings = settings_for(*write_identity(tmp_path, issue_webpki_cert(ca, "localhost")))
    tls = ReloadableTLS(settings, _trust_roots=trusted_roots(ca))
    previous = tls.context
    write_identity(tmp_path, issue_webpki_cert(ca, "localhost"))
    original_load = ssl.SSLContext.load_cert_chain

    def racing_load(context, *args, **kwargs):
        original_load(context, *args, **kwargs)
        write_identity(tmp_path, issue_webpki_cert(ca, "localhost"))

    monkeypatch.setattr(ssl.SSLContext, "load_cert_chain", racing_load)
    assert not tls.reload_if_changed()
    assert tls.context is previous


def test_expiry_warning_is_emitted_before_renewal_becomes_an_outage(tmp_path, caplog):
    now = datetime.now(timezone.utc)
    ca = trustme.CA()
    cert = issue_webpki_cert(ca, "localhost", not_after=now + timedelta(days=10))
    tls = ReloadableTLS(settings_for(*write_identity(tmp_path, cert)), _trust_roots=trusted_roots(ca))
    assert "check ACME renewal immediately" in caplog.text
    caplog.clear()
    assert not tls.reload_if_changed()
    assert "check ACME renewal immediately" not in caplog.text


def test_acme_hook_publishes_complete_identity_and_rejects_broken_pair(tmp_path, monkeypatch):
    script = Path(__file__).parents[1] / "deploy" / "acme" / "deploy.py"
    spec = importlib.util.spec_from_file_location("acme_deploy", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Production runs as root and publishes to uid 10001; tests need no privileges.
    monkeypatch.setattr(module, "SERVER_UID", os.getuid())
    monkeypatch.setattr(module.os, "fchown", lambda *_: None)
    ca = trustme.CA()
    lineage, destination = tmp_path / "lineage", tmp_path / "runtime" / "server.pem"
    first = issue_webpki_cert(ca, "localhost")
    write_identity(lineage, first)
    module.publish(lineage, destination, "localhost", _trust_roots=trusted_roots(ca))
    first_identity = destination.read_bytes()
    assert destination.stat().st_mode & 0o777 == 0o400
    settings = settings_for(destination, destination)
    tls = ReloadableTLS(settings, _trust_roots=trusted_roots(ca))
    first_context = tls.context

    # This simulates two partially replaced ACME files; published identity stays intact.
    (lineage / "privkey.pem").write_bytes(issue_webpki_cert(ca, "localhost").private_key_pem.bytes())
    with pytest.raises(ssl.SSLError):
        module.publish(lineage, destination, "localhost", _trust_roots=trusted_roots(ca))
    assert destination.read_bytes() == first_identity
    assert not list(destination.parent.glob(".identity-*"))

    # A correct leaf/key pair is insufficient when its intermediate is missing.
    intermediate = ca.create_child_ca()
    incomplete = issue_webpki_cert(intermediate, "localhost")
    write_identity(lineage, incomplete)
    (lineage / "fullchain.pem").write_bytes(incomplete.cert_chain_pems[0].bytes())
    with pytest.raises(VerificationError):
        module.publish(lineage, destination, "localhost", _trust_roots=trusted_roots(ca))
    assert destination.read_bytes() == first_identity

    write_identity(lineage, issue_webpki_cert(ca, "localhost"))
    module.publish(lineage, destination, "localhost", _trust_roots=trusted_roots(ca))
    assert tls.reload_if_changed()
    assert tls.context is not first_context
    inode = destination.stat().st_ino
    module.publish(lineage, destination, "localhost", _trust_roots=trusted_roots(ca))
    assert destination.stat().st_ino == inode
