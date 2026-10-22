"""Docker health probe for certificate availability and renewal-loop liveness."""
import time
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509

runtime = Path("/run/wol-tls")
if time.time() - (runtime / "renewal-ok").stat().st_mtime >= 25 * 3600:
    raise SystemExit("ACME renewal check is overdue")
certs = x509.load_pem_x509_certificates((runtime / "server.pem").read_bytes())
now = datetime.now(timezone.utc)
if not certs or not all(cert.not_valid_before_utc <= now < cert.not_valid_after_utc for cert in certs):
    raise SystemExit("TLS certificate expired")
