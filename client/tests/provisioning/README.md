# Security 2 interoperability tests

The SRP tests need JDK 17+ and the sources of the pinned Espressif Android SDK
(`lib-2.4.4`, commit `b83b78543fcd7ae24c9acbefdc17cad3ed4a3607`). They do not
need an Android device, Gradle, or Protobuf:

```sh
python3 client/tests/provisioning/run_srp_tests.py /path/to/esp-idf-provisioning-android
```

The properties files contain **test-only** credentials and deterministic private
values. Expected results were calculated independently using the server-side
equations and byte serialization in ESP-IDF `components/protocomm/src/crypto/srp6a/esp_srp.c`,
commit `fcae32885b0296b32044cb99ecbdc50d98dddb83`. The profile is the 3072-bit
group with generator 5 and SHA-512. Fields `a` and `b` are hexadecimal client
and server private values; `A`, `B`, `K`, `M1`, and `M2` are expected wire values.

The vectors cover a normal exchange, a salt beginning with zero, a shared key
beginning with zero, and a client proof beginning with zero. Salt and hash
outputs retain their full byte lengths. These cases catch lossy conversion
through `BigInteger`, which would otherwise fail intermittently for valid
factory credentials. Every vector also checks wrong passwords, altered server
proofs, replay, invalid public values, and key access before authentication or
after authentication failure.

These tests verify the cryptographic exchange; physical Android/ESP32 testing
is still required for Bluetooth permissions, connection lifecycle, and Wi-Fi.
