from pathlib import Path

import pytest
import trustme

from helpers import issue_webpki_cert, trusted_roots
from wol_server.config import ConfigError, Settings
from wol_server.tls import ReloadableTLS


def environment(cert_file: Path, key_file: Path) -> dict[str, str]:
    return {
        "CLIENT_PORT": "8443", "DEVICE_PORT": "8444", "TOKEN_PEPPER": "x" * 32,
        "DATABASE_URL": "postgresql://unused", "TLS_SERVER_NAME": "wol.example.com",
        "TLS_CERT_FILE": str(cert_file), "TLS_KEY_FILE": str(key_file),
    }


def test_acme_symlink_paths_follow_renewed_generation(tmp_path):
    ca = trustme.CA()
    cert_link, key_link = tmp_path / "fullchain.pem", tmp_path / "privkey.pem"

    def generation(number):
        cert = issue_webpki_cert(ca, "wol.example.com")
        cert_path, key_path = tmp_path / f"cert{number}.pem", tmp_path / f"key{number}.pem"
        cert.cert_chain_pems[0].write_to_path(cert_path)
        cert.private_key_pem.write_to_path(key_path)
        return cert_path, key_path

    first_cert, first_key = generation(1)
    cert_link.symlink_to(first_cert)
    key_link.symlink_to(first_key)
    settings = Settings.from_env(environment(cert_link, key_link), tmp_path)
    assert settings.cert_file == cert_link
    assert settings.key_file == key_link
    tls = ReloadableTLS(settings, _trust_roots=trusted_roots(ca))
    original = tls.context

    second_cert, second_key = generation(2)
    cert_link.unlink()
    key_link.unlink()
    cert_link.symlink_to(second_cert)
    key_link.symlink_to(second_key)
    assert tls.reload_if_changed()
    assert tls.context is not original


@pytest.mark.parametrize("interval", ["0", "-1", "3601", "nan", ""])
def test_invalid_reload_interval_is_rejected(tmp_path, interval):
    cert = tmp_path / "certificate.pem"
    cert.touch()
    env = environment(cert, cert)
    env["TLS_RELOAD_INTERVAL"] = interval
    with pytest.raises(ConfigError, match="TLS_RELOAD_INTERVAL"):
        Settings.from_env(env, tmp_path)


@pytest.mark.parametrize("name", ["", "*.example.com", "https://example.com", "host name.example", "-host.example"])
def test_tls_identity_requires_an_exact_dns_name(tmp_path, name):
    cert = tmp_path / "certificate.pem"
    cert.touch()
    env = environment(cert, cert)
    env["TLS_SERVER_NAME"] = name
    with pytest.raises(ConfigError, match="TLS_SERVER_NAME"):
        Settings.from_env(env, tmp_path)
