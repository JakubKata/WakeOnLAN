#!/usr/bin/env python3
"""Generate unique encrypted factory NVS and a private QR label for one NEW unit.

Run from the ESP-IDF 5.5 Python environment. Output is manufacturing key material;
never commit it or reuse it on another unit. This is not a customer setup step.
"""
from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys


def generate(output: Path, idf: Path) -> None:
    source = idf / "tools/esp_prov/security/srp6a.py"
    if not source.is_file():
        raise ValueError("ESP-IDF 5.5.1 tools/esp_prov/security/srp6a.py not found")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    # Load the official SRP implementation without importing the BLE/GUI tooling.
    sys.path.insert(0, str(idf / "tools/esp_prov"))
    spec = importlib.util.spec_from_file_location("idf_srp6a", source)
    if spec is None or spec.loader is None:
        raise ValueError("Cannot load ESP-IDF SRP implementation")
    srp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(srp)
    name = "WOL_" + secrets.token_hex(6).upper()
    username = secrets.token_urlsafe(16)
    password = secrets.token_urlsafe(32)
    salt, verifier = srp.generate_salt_and_verifier(username, password, len_s=16)
    # Do not pad salt: changing its byte representation would change x and invalidate v.
    while len(salt) != 16:
        salt, verifier = srp.generate_salt_and_verifier(username, password, len_s=16)
    # Verifier is an integer, so fixed-width big-endian padding preserves its value.
    verifier = verifier.rjust(384, b"\0")
    if len(salt) != 16 or len(verifier) != 384:
        raise ValueError("Unexpected SRP-3072 parameters")
    label = {"ver": "v1", "name": name, "transport": "ble", "security": 2,
             "username": username, "pop": password}
    label_text = json.dumps(label, separators=(",", ":"))
    (output / "label.json").write_text(label_text + "\n", encoding="utf-8")
    import qrcode
    from qrcode.image.svg import SvgPathImage
    qrcode.make(label_text, image_factory=SvgPathImage).save(output / "label.svg")
    with (output / "factory.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerows([
            ("key", "type", "encoding", "value"),
            ("factory", "namespace", "", ""),
            ("name", "data", "string", name),
            ("salt", "data", "hex2bin", salt.hex()),
            ("verifier", "data", "hex2bin", verifier.hex()),
        ])
    subprocess.run([
        sys.executable, "-m", "esp_idf_nvs_partition_gen", "encrypt",
        str(output / "factory.csv"), "nvs.bin", "0x6000",
        "--keygen", "--keyfile", "nvs_keys.bin", "--outdir", str(output),
    ], check=True)
    for path in output.rglob("*"):
        if path.is_file():
            path.chmod(0o600)
    print(f"Created factory files in {output}; keep the QR and NVS keys private.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="new private directory per device")
    parser.add_argument("--idf-path", type=Path, default=os.environ.get("IDF_PATH"), required=not os.environ.get("IDF_PATH"))
    args = parser.parse_args()
    previous_umask = os.umask(0o077)
    try:
        generate(args.output.resolve(), args.idf_path.resolve())
    finally:
        os.umask(previous_umask)


if __name__ == "__main__":
    main()
