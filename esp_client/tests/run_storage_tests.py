"""Compile and test production credential storage with fault-injected host NVS.

Requires a C++17 compiler and OpenSSL development headers/libraries.
"""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="storage-test-", dir=os.environ.get("TMPDIR", Path.cwd())) as build:
    executable = str(Path(build) / "test-credentials")
    subprocess.run([
        os.environ.get("CXX", "g++"), "-std=c++17", "-Wall", "-Wextra", "-Werror", "-pthread",
        "-I", str(root / "tests/include"), "-I", str(root / "components/storage/include"),
        "-I", str(root / "components/updates/include"),
        "-I", str(root / "components/onboarding/include"),
        str(root / "components/storage/src/credentials.cpp"), str(root / "tests/test_credentials.cpp"),
        "-lcrypto", "-o", executable,
    ], check=True)
    subprocess.run([executable], check=True)
