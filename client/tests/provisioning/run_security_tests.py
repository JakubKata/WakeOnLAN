"""Compile and run the real Security2 adapter without Android or Gradle.

Arguments are a checkout of Espressif lib-2.4.4, protoc (3.21.9), and the
protobuf-javalite (3.18.0) JAR. The caller supplies pinned upstream dependencies.
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
    parser.add_argument("protoc", type=Path)
    parser.add_argument("protobuf", type=Path)
    args = parser.parse_args()
    test_dir = Path(__file__).resolve().parent
    client_dir = test_dir.parents[1]
    source = args.sdk.resolve() / "provisioning/src/main"
    names = ("BigIntegerUtils", "SRP6ClientCredentials", "SRP6CryptoParams", "SRP6Exception",
             "SRP6Routines", "XRoutine", "XRoutineWithUserIdentity")
    sources = [source / "java/com/espressif/provisioning/srp6a" / (name + ".java") for name in names]
    sources.append(source / "java/com/espressif/provisioning/security/Security.java")
    sources.extend((client_dir / "modules/wol-provisioning/android/src/main/java/com/wol/provisioning/security").glob("*.java"))
    sources.append(test_dir / "VerifiedSecurity2Test.java")
    java = os.environ.get("JAVA", shutil.which("java") or "java")
    with tempfile.TemporaryDirectory(prefix="security2-test-", dir=os.environ.get("TMPDIR", Path.cwd())) as temp:
        build = Path(temp)
        subprocess.run([str(args.protoc.resolve()), "-I", str(source / "proto"), f"--java_out=lite:{build}",
                        *(str(path) for path in sorted((source / "proto").glob("*.proto")))], check=True)
        sources.extend((build / "espressif").glob("*.java"))
        classes = build / "classes"
        classes.mkdir()
        subprocess.run([java, "--module", "jdk.compiler/com.sun.tools.javac.Main", "-cp", str(args.protobuf.resolve()),
                        "-d", str(classes), *(str(path) for path in sources)], check=True)
        subprocess.run([java, "-cp", os.pathsep.join((str(classes), str(args.protobuf.resolve()))),
                        "com.wol.provisioning.security.VerifiedSecurity2Test", str(test_dir / "vectors")], check=True)


if __name__ == "__main__":
    main()
