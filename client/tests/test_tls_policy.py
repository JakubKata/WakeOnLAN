"""Exercise the installed native TLS policy with real certificates (JDK + trustme).

Run after npm ci: server/.venv/bin/python -m pytest client/tests/test_tls_policy.py
The same Java policy is compiled into the Android TCP module by patch-package.
"""

import datetime
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import threading

import pytest
import trustme


CLIENT = Path(__file__).resolve().parents[1]
POLICY = CLIENT / "node_modules/react-native-tcp-socket/android/src/main/java/com/asterinet/react/tcpsocket/TlsSocketPolicy.java"


@pytest.fixture(scope="module")
def java_client(tmp_path_factory):
    if not shutil.which("java"):
        pytest.skip("JDK is required for native TLS policy tests")
    assert POLICY.exists(), "Run npm ci with lifecycle scripts enabled to install the TLS patch"
    work = tmp_path_factory.mktemp("java_tls")
    harness = work / "PolicyClient.java"
    harness.write_text('''package com.asterinet.react.tcpsocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import javax.net.ssl.*;
public class PolicyClient {
    public static void main(String[] args) throws Exception {
        KeyStore roots = KeyStore.getInstance(KeyStore.getDefaultType());
        roots.load(null, null);
        try (var input = Files.newInputStream(Path.of(args[0]))) {
            roots.setCertificateEntry("test-ca", CertificateFactory.getInstance("X.509").generateCertificate(input));
        }
        TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trust.init(roots);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, trust.getTrustManagers(), null);
        try (Socket tcp = new Socket("127.0.0.1", Integer.parseInt(args[1]));
             SSLSocket tls = (SSLSocket) context.getSocketFactory().createSocket(tcp, args[2], tcp.getPort(), true)) {
            TlsSocketPolicy.handshake(tls);
            System.out.println("VERIFIED " + tls.getSession().getProtocol());
        }
    }
}
''')
    compiler = ["javac"] if shutil.which("javac") else ["java", "--module", "jdk.compiler/com.sun.tools.javac.Main"]
    subprocess.run([*compiler, "-d", str(work), str(POLICY), str(harness)], check=True, capture_output=True)
    return work


def handshake(java_client, tmp_path, trusted_ca, certificate):
    ca_file = tmp_path / "ca.pem"
    trusted_ca.cert_pem.write_to_path(ca_file)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    certificate.configure_cert(context)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(15)
        port = listener.getsockname()[1]

        def serve():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(10)
                    with context.wrap_socket(connection, server_side=True):
                        pass
            except (ssl.SSLError, TimeoutError, OSError):
                pass  # Rejected peers deliberately abort their handshake.

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        result = subprocess.run(
            ["java", "-cp", str(java_client), "com.asterinet.react.tcpsocket.PolicyClient", str(ca_file), str(port), "wol.example.test"],
            capture_output=True, text=True, timeout=15,
        )
        worker.join(timeout=15)
        assert not worker.is_alive()
    return result


def test_renewed_leaf_accepted_without_changing_trust(java_client, tmp_path):
    ca = trustme.CA()
    for certificate in (ca.issue_cert("wol.example.test"), ca.issue_cert("wol.example.test")):
        result = handshake(java_client, tmp_path, ca, certificate)
        assert result.returncode == 0, result.stderr
        assert "VERIFIED TLSv1." in result.stdout


def test_wrong_hostname_rejected(java_client, tmp_path):
    ca = trustme.CA()
    result = handshake(java_client, tmp_path, ca, ca.issue_cert("attacker.example.test"))
    assert result.returncode != 0
    assert "SSLHandshakeException" in result.stderr


def test_untrusted_ca_rejected(java_client, tmp_path):
    result = handshake(java_client, tmp_path, trustme.CA(), trustme.CA().issue_cert("wol.example.test"))
    assert result.returncode != 0
    assert "SSLHandshakeException" in result.stderr


def test_expired_leaf_rejected(java_client, tmp_path):
    ca = trustme.CA()
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = ca.issue_cert("wol.example.test", not_before=now - datetime.timedelta(days=2), not_after=now - datetime.timedelta(days=1))
    result = handshake(java_client, tmp_path, ca, certificate)
    assert result.returncode != 0
    assert "SSLHandshakeException" in result.stderr
