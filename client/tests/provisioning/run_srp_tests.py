"""Run reference-vector SRP tests against the pinned Espressif SDK sources.

Usage: python3 tests/provisioning/run_srp_tests.py /path/to/esp-idf-provisioning-android
Requires a JDK 17+, but neither Android SDK nor Gradle.
"""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sdk", type=Path)
    args = parser.parse_args()
    test_dir = Path(__file__).resolve().parent
    client_dir = test_dir.parents[1]
    sdk_dir = args.sdk.resolve() / "provisioning/src/main/java/com/espressif/provisioning/srp6a"
    names = ("BigIntegerUtils", "SRP6ClientCredentials", "SRP6CryptoParams", "SRP6Exception",
             "SRP6Routines", "XRoutine", "XRoutineWithUserIdentity")
    sources = [sdk_dir / (name + ".java") for name in names]
    sources.extend([
        client_dir / "modules/wol-provisioning/android/src/main/java/com/wol/provisioning/security/VerifiedSrpClient.java",
        test_dir / "SrpInteropTest.java",
    ])
    java = os.environ.get("JAVA", shutil.which("java") or "java")
    with tempfile.TemporaryDirectory(prefix="srp-test-", dir=os.environ.get("TMPDIR", Path.cwd())) as build:
        subprocess.run([java, "--module", "jdk.compiler/com.sun.tools.javac.Main", "-d", build,
                        *(str(source) for source in sources)], check=True)
        vectors = sorted((test_dir / "vectors").glob("*.properties"))
        subprocess.run([java, "-cp", build, "com.wol.provisioning.security.SrpInteropTest",
                        *(str(vector) for vector in vectors)], check=True)


if __name__ == "__main__":
    main()
