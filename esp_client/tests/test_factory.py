"""Factory enrollment regression checks; run with the ESP-IDF Python environment."""
import csv
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
spec = importlib.util.spec_from_file_location("factory", TOOLS / "provision_factory.py")
factory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(factory)


@unittest.skipUnless(os.environ.get("IDF_PATH"), "requires the verified ESP-IDF SRP implementation")
class FactoryTests(unittest.TestCase):
    def test_unique_private_parameters_and_encrypted_partition_roundtrip(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            units = [root / "one", root / "two"]
            labels = []
            old_umask = os.umask(0o077)
            try:
                for output in units:
                    factory.generate(output, Path(os.environ["IDF_PATH"]))
                    label = json.loads((output / "label.json").read_text())
                    labels.append(label)
                    self.assertEqual((label["transport"], label["security"]), ("ble", 2))
                    with (output / "factory.csv").open() as source:
                        rows = {row["key"]: row["value"] for row in csv.DictReader(source)}
                    self.assertNotIn(label["pop"], (output / "factory.csv").read_text())
                    self.assertEqual(len(bytes.fromhex(rows["salt"])), 16)
                    self.assertEqual(len(bytes.fromhex(rows["verifier"])), 384)
                    srp_spec = importlib.util.spec_from_file_location(
                        "test_srp", Path(os.environ["IDF_PATH"]) / "tools/esp_prov/security/srp6a.py")
                    srp = importlib.util.module_from_spec(srp_spec)
                    srp_spec.loader.exec_module(srp)
                    n, g = srp.get_ng(srp.NG_3072)
                    x = srp.calculate_x(srp.hashlib.sha512, bytes.fromhex(rows["salt"]), label["username"], label["pop"])
                    self.assertEqual(int(rows["verifier"], 16), pow(g, x, n))
                    for path in output.rglob("*"):
                        if path.is_file():
                            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                    self.assertEqual((output / "nvs.bin").stat().st_size, 0x6000)
                    self.assertEqual((output / "keys/nvs_keys.bin").stat().st_size, 0x1000)
                    subprocess.run([sys.executable, "-m", "esp_idf_nvs_partition_gen", "decrypt",
                                    str(output / "nvs.bin"), str(output / "keys/nvs_keys.bin"),
                                    str(output / "decrypted.bin")], check=True, stdout=subprocess.DEVNULL)
                    subprocess.run([sys.executable, "-m", "esp_idf_nvs_partition_gen", "generate",
                                    str(output / "factory.csv"), str(output / "plain.bin"), "0x6000"],
                                   check=True, stdout=subprocess.DEVNULL)
                    self.assertEqual((output / "decrypted.bin").read_bytes(), (output / "plain.bin").read_bytes())
                self.assertNotEqual(labels[0]["pop"], labels[1]["pop"])
                self.assertNotEqual(labels[0]["name"], labels[1]["name"])
                with self.assertRaises(FileExistsError):
                    factory.generate(units[0], Path(os.environ["IDF_PATH"]))
            finally:
                os.umask(old_umask)


if __name__ == "__main__":
    unittest.main()
