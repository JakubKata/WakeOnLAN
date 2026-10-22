"""Host regressions for delayed UNPAIRED; no ESP-IDF or board required."""
import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def unpair_race_program(tmp_path_factory):
    executable = tmp_path_factory.mktemp("unpair-race") / "test-unpair-race"
    result = subprocess.run([
        os.environ.get("CXX", "g++"), "-std=c++17", "-Wall", "-Wextra", "-Werror", "-pthread",
        "-I", str(ROOT / "tests/include"),
        "-I", str(ROOT / "components/storage/include"),
        "-I", str(ROOT / "components/updates/include"),
        "-I", str(ROOT / "components/onboarding/include"),
        str(ROOT / "components/storage/src/credentials.cpp"),
        str(ROOT / "tests/test_unpair_claim_race.cpp"),
        "-lcrypto", "-o", str(executable),
    ], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, "Failed to compile unpair regressions:\n" + result.stdout + result.stderr
    return executable


@pytest.mark.parametrize("scenario", [
    "stale_empty", "stale_nonempty", "matching_claim", "ble_after_unpair",
    "failed_write", "failed_commit", "ambiguous_commit", "duplicate_unpair",
])
def test_unpair_storage_regression(unpair_race_program, scenario):
    result = subprocess.run(
        [str(unpair_race_program), scenario], capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr
