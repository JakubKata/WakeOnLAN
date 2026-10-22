"""Execute real QR validation and pairing-screen handlers without an Android device.

Requires Node and the client dependencies installed by npm ci. The harness keeps
React state/effects deterministic and replaces only UI/native/network boundaries.
"""
from pathlib import Path
import shutil
import subprocess

import pytest


CLIENT = Path(__file__).resolve().parents[1]


def run_scenario(name: str) -> None:
    if not shutil.which("node"):
        pytest.skip("Node is required for pairing UI tests")
    assert (CLIENT / "node_modules/typescript").is_dir(), "Run npm ci before the pairing UI tests"
    result = subprocess.run(
        ["node", str(CLIENT / "tests/pairing_harness.cjs"), name],
        cwd=CLIENT, capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("scenario", ["setup_code", "new_device", "owned_device", "stale_connect", "background_refresh"])
def test_pairing_behavior(scenario):
    run_scenario(scenario)
