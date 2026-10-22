# WoL server protocol (v3)

[Polski](PROTOCOL.pl.md) | **English**

Two TLS ports (min. TLS 1.2), both using the same server certificate:

- `CLIENT_PORT` (default 8443): mobile/desktop app,
- `DEVICE_PORT` (default 8444): ESP32 devices.

The app validates the server chain and hostname against the Android system trust store. The ESP32 uses the ESP-IDF root CA bundle with chain, hostname and validity checks enabled. A public DNS name and a certificate from a CA trusted by both stores are required. The server certificate is renewed through ACME; it is not embedded in either client. See [deployment and certificate renewal](../README.md).

## Frame

One message = one JSON object terminated by `\n`. Messages to the server may be at most 4096 bytes (not counting the terminating `\n`); server responses have no such limit (e.g. `LIST_TARGETS` with 64 targets is up to about 55 KB when the names consist of emoji), so the client should accept lines up to 64 KiB:

```
{"COMMAND":[arg1,arg2,...]}\n
```

- The server sends ASCII only (non-ASCII characters as `\uXXXX`).
- Argument types are checked strictly (`"1"` is not `1`, `true` is not a number).
- Response: `{"ACK":[...]}` or `{"NACK":["error_code"]}`.
- Invalid JSON gives `NACK bad_frame` and the connection stays open. A line that is too long gives `NACK frame_too_long` and a disconnect.
- The client sends the next request only after receiving the response to the previous one.

Timeouts:
- 5 s for the TLS handshake,
- 30 s for authentication, counted from when the connection is established. Further messages before logging in do not extend this deadline, and the third invalid frame before logging in closes the connection,
- 300 s of inactivity for a logged-in client (the client may send `PING`).

Connection limits are counted separately for each port, so flooding the client port does not block ESP devices and vice versa: 20 per IP address and 1000 per port, of which at most 5 per IP address and 256 per port may be not yet authenticated (including those in the TLS handshake). On an internet-facing server it is worth additionally limiting connections in the firewall, e.g. `iptables -A INPUT -p tcp --syn -m multiport --dports 8443,8444 -m connlimit --connlimit-above 20 -j REJECT`.

## Device pairing over BLE

1. The signed-in app scans the device's unique QR label and discovers its BLE service.
2. Espressif Security 2, patch version 1, authenticates the provisioning session using SRP6a and encrypts it with AES-GCM. The per-device QR password is proof of possession; the BLE name is only a discovery hint.
3. Through the encrypted `wol-claim` endpoint the app reads the device identity, scans nearby Wi-Fi networks, and collects the selected SSID and password.
4. The app sends `CREATE_CLAIM device_name device_id` to the server and receives `ACK [claim_token, 600]`.
5. The app sends the token and current Unix time through the authenticated BLE session, then provisions Wi-Fi through the standard Espressif endpoint. The Wi-Fi password never goes to the server.
6. The device connects to the server over verified TLS, authenticates or redeems the claim, and the app confirms pairing only when `LIST_DEVICES` contains that ID with `online: true` on the signed-in account.

The device generates 32 random bytes once, before contacting the server:

- `device_secret = base64url(random_bytes)` without padding (43 characters),
- `device_id = base64url(SHA256(random_bytes))` without padding (43 characters).

The identity is persisted atomically in encrypted NVS before enrollment. The secret stays on the device and is sent only to the TLS server; the app receives the ID, not the secret. The server verifies the ID/secret relation on new claims, so knowing an ID alone cannot reserve it with a different secret. This is possession-based enrollment, not manufacturer attestation.

| Sender | Request | Result |
|---|---|---|
| App → server | `CREATE_CLAIM device_name device_id` | `ACK [claim_token, 600]` |
| ESP → server | `DEVICE_AUTH device_id device_secret` | `ACK []` when already enrolled |
| ESP → server | `DEVICE_CLAIM claim_token device_id device_secret` | `ACK [device_id]` |

- The 128-bit claim token is valid for 10 minutes and bound to both the account and device ID. A new `CREATE_CLAIM` replaces that account's previous unused claim; an already enrolled ID is rejected with `duplicate`. Password changes, password resets and `LOGOUT_ALL` invalidate unused claims.
- Claim consumption, device creation and the ownership check are one transaction. An existing device cannot be reassigned by presenting another account's claim.
- If a claim response is lost, the device still has its persisted credentials. It tries `DEVICE_AUTH` on reconnect. Repeating the original successful claim with the same token, ID and secret is idempotent even after the original token expiry; no new credentials or owner are issued.
- After successful authentication or claim the connection is authenticated immediately. A new connection with the same device ID replaces the previous one.
- Invalid credentials, a network outage or an NVS error do not authorize erasing identity or taking over an owned device. Wi-Fi recovery requires the physical setup action and the QR credential; it preserves identity and server ownership.
- Manual token entry and manual device-secret rotation are not part of this protocol. The app never displays a cloud claim token or device secret.

### Local provisioning endpoint

`wol-claim` carries UTF-8 JSON within the authenticated Espressif Security 2 session. It is not an unauthenticated HTTP endpoint.

| Request | Response / purpose |
|---|---|
| `{"op":"info"}` | `{"device_id":"…","paired":false}`; `paired` describes local enrollment state |
| `{"op":"claim","token":"…","time":1780000000}` | `{"ok":true}` after validating and persisting the claim for an unpaired device |
| `{"op":"configure","time":1780000000}` | Wi-Fi/time recovery for an already paired device; does not change ownership |

BLE service UUID: `021a9004-0382-4aea-bff4-6b3f1c5adfb4`. An unpaired unit opens setup for ten minutes on boot; a paired unit requires an active-low setup GPIO held for three seconds at power-on (default GPIO 4, verify the board). Five failed authentication attempts close the window. QR fields: `{"ver":"v1","name":"WOL_…","transport":"ble","security":2,"username":"…","pop":"…"}`. Each unit has its own username/password and matching SRP salt/verifier provisioned during manufacturing. Never ship a shared test password. Keep QR credentials out of logs, analytics and public repositories.

## Client commands (`CLIENT_PORT`)

Before logging in:

| Command | Arguments | ACK |
|---|---|---|
| `REGISTER` | name, email, password | session_token, name |
| `LOGIN` | name, password | session_token, name |
| `RESUME` | session_token | name |
| `REQUEST_PASSWORD_RESET` | email | (empty); the code is sent by e-mail |
| `RESET_PASSWORD` | email, code, new_password | session_token, name; all other sessions invalidated |

After logging in:

| Command | Arguments | ACK |
|---|---|---|
| `PING` | (none) | `PONG` response; before logging in `NACK unauthenticated` |
| `LOGOUT` | (none) | (empty), then disconnect |
| `LOGOUT_ALL` | (none) | (empty), invalidates all tokens, reset codes and claims, then disconnects |
| `CHANGE_PASSWORD` | old, new | new session_token; other sessions, reset codes and claims are invalidated |
| `CHANGE_NAME` | new_name, password | new_name |
| `DELETE_ACCOUNT` | password | (empty); devices receive `UNPAIRED`, then disconnects |
| `CREATE_CLAIM` | device_name, device_id | claim_token, ttl_seconds |
| `LIST_DEVICES` | (none) | `[{id, name, online, last_seen_at}]` |
| `RENAME_DEVICE` | device_id, name | device_id, name |
| `REMOVE_DEVICE` | device_id | device_id; the ESP receives `UNPAIRED` |
| `ADD_TARGET` | device_id, mac, name | `{id, device_id, mac, name}` |
| `LIST_TARGETS` | (none) | `[{id, device_id, mac, name}]` |
| `RENAME_TARGET` | target_id (int), name | target_id, name |
| `ASSIGN_TARGET` | target_id (int), device_id | target_id, device_id |
| `REMOVE_TARGET` | target_id (int) | target_id |
| `WAKE_UP` | target_id (int) | target_id, only after the ESP confirms; per account 10 at once, then 1 every 6 s (`rate_limited`) |

The session token is valid for 30 days from its last use. The app stores it in secure storage (Keychain/Keystore) instead of the password.

Session invalidation (`CHANGE_PASSWORD`, `RESET_PASSWORD`, `LOGOUT_ALL`) is final: a `LOGIN` or `RESUME` running at the same time ends with `NACK invalid_credentials` or `NACK invalid_token` respectively. At least once a minute the server checks whether the session of a logged-in connection still exists. If it does not, any command gets `NACK invalid_token` and the connection is closed.

Login: failed attempts are counted per (account, IP address): 10 attempts at once, then 1 per minute, and more loosely per account: 100 attempts at once, then 1 every 36 s (about 100 per hour). So a stranger cannot lock the owner out of logging in from a different address. An attempt is taken from the limit before the password is checked and given back after a successful login, so concurrent attempts over several connections count too.

`REGISTER` responds with `account_exists` when the name or e-mail is taken. This is a deliberate trade-off: the username has to be unique and visible at registration anyway. Probing addresses is restricted by a per-IP limit and a separate per-e-mail limit (3 attempts at once, then 1 every 10 minutes).

Field rules:
- name: `[A-Za-z0-9_.-]{3,32}`, case-insensitive,
- password: 8–128 characters,
- device and target names: 1–64 characters without control characters,
- MAC: `AA:BB:CC:DD:EE:FF`, `AA-BB-...`, `AABB.CCDD.EEFF` or `AABBCCDDEEFF`, no multicast/broadcast addresses.

After a device is removed, its targets remain with `device_id = null`. `ASSIGN_TARGET` attaches them to another device.

### Password recovery

```
App    -> Server : REQUEST_PASSWORD_RESET "john@example.com" -> ACK []
Server -> e-mail : code in the form "7K3QD-9XW2M"
App    -> Server : RESET_PASSWORD "john@example.com" "7K3QD-9XW2M" "new password"
                                                              -> ACK [session_token, name]
```

- `REQUEST_PASSWORD_RESET` always responds with `ACK []` (also for an unknown address), so it cannot be used to check whether an e-mail is registered. The app shows a message along the lines of "if the account exists, we have sent a code".
- The code has 10 characters (digits and letters except I, L, O, U), is valid for 15 minutes and is single-use. Case, spaces and hyphens do not matter; `O`, `I`, `L` are read as `0`, `1`, `1`.
- A new request invalidates the previous code. Attempts per (e-mail, IP address) pair are limited to 5 at once, then 1 per minute, and after 50 failed attempts in total the code is discarded. The high total limit means a stranger cannot "burn" the owner's code, and with about 50 bits of entropy guessing the code is still infeasible. `CHANGE_PASSWORD` also invalidates the code.
- A wrong, expired or used code gives `NACK invalid_token`.
- After a successful reset all sessions and claims of the account are invalidated, and the connection is immediately logged in with the new token.
- Without SMTP configured, both commands give `NACK reset_unavailable`.

## ESP commands (`DEVICE_PORT`)

ESP -> server:

| Command | Arguments | Server response |
|---|---|---|
| `DEVICE_CLAIM` | claim_token, device_id, device_secret | `ACK [device_id]`; identity must match the secret and the claim |
| `DEVICE_AUTH` | device_id, device_secret | `ACK []`; a wrong or malformed secret gives `NACK invalid_credentials` |
| `PING` | (none) | `PONG` (only after authentication) |
| `PONG` | (none) | no response |
| `WAKE_ACK` | request_id | no response |

Server -> ESP:

| Command | Arguments | Expected ESP reaction |
|---|---|---|
| `PING` | (none) | `PONG` |
| `WAKE_UP` | request_id, mac | send the magic packet, then `WAKE_ACK request_id` |
| `UNPAIRED` | (none) | clear enrollment state and pending claim, retain identity; the next boot opens the bounded BLE setup window |

- The server sends `PING` when nothing has arrived for 30 s, and disconnects after 90 s of silence.
- `WAKE_UP` on the client side ends with `NACK device_unreachable` if `WAKE_ACK` does not arrive within 5 s.
- The ESP never responds to `ACK`/`NACK`, to avoid a loop.
- The ESP should use cJSON (the `json` component in ESP-IDF) instead of a hand-written parser. Frames nested deeper than 4 levels are rejected before parsing, because a recursive parser could overflow the task stack.
- Socket writes have a 10 s deadline. If the server stops receiving data, the ESP closes the connection and reconnects.

### Securing data on the ESP32

`device_secret` is enough to impersonate the device, so flash and NVS must be encrypted:

- [esp_client/sdkconfig.defaults](../esp_client/sdkconfig.defaults) enables flash encryption (Development mode, flashing over UART is still possible) and NVS encryption. The NVS keys live in the encrypted `nvs_keys` partition ([partitions.csv](../esp_client/partitions.csv)) and are generated on first boot.
- Production build: `idf.py -B build-release -D SDKCONFIG=sdkconfig.release -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.release" build`. The separate `sdkconfig.release` file is required because ESP-IDF reads `SDKCONFIG_DEFAULTS` only when it creates a new `sdkconfig`; an existing `sdkconfig` from a development build would silently override the release profile. The [sdkconfig.defaults.release](../esp_client/sdkconfig.defaults.release) profile switches encryption to Release mode and enables Secure Boot v2. You must generate a signing key beforehand: `espsecure.py generate_signing_key --version 2 secure_boot_signing_key.pem`. Keep it outside the repository, because without it you can no longer flash new firmware.
- Even Development mode writes the encryption key to eFuse on first boot. It can then be disabled only a limited number of times (three on the ESP32). Release mode and Secure Boot v2 are completely irreversible. Secure Boot v2 on a plain ESP32 requires chip revision 3.0 or newer.
- Factory provisioning and partition changes need a controlled manufacturing/service procedure. Do not erase a deployed device as a routine update: that would destroy its persisted identity and Wi-Fi settings.

### Firmware updates and trust-store maintenance

The partition layout has two OTA slots and rollback metadata and requires at least 4 MB flash. In the release profile, signed HTTPS updates require Secure Boot, anti-rollback and `WOL_ENABLE_OTA`; configure a fixed `WOL_FIRMWARE_URL` for the exact product/target. Publish a signed image with the same project name and a strictly newer numeric `PROJECT_VER` (`major.minor.patch`). Its secure version must not decrease or fall below the eFuse minimum. The fixed URL must return HTTP 200 directly with a known `Content-Length` that fits the OTA slot; redirects, chunked transfers and unsigned images are rejected. A download has a ten-minute overall deadline.

A stable image schedules update checks independently of relay authentication, after an initial 30–330 second delay and then every 24 hours plus up to one hour of jitter. Checks wait until BLE setup has closed. This allows recovery from relay trust problems while the configured update host remains trusted. An image awaiting boot confirmation does not start further updates until cloud authentication confirms it. The inactive slot is written first. The new image is confirmed only after it authenticates to the cloud; if it does not do so within 120 seconds, the bootloader rolls back. Normal OTA preserves NVS. The root CA bundle is updated inside the signed firmware image. Publish overlap roots before changing the server or firmware-host certificate chain. Keep a working trusted download chain for supported offline devices; OTA cannot bootstrap itself through a chain its old firmware no longer trusts.

First migration from the old single-app partition layout requires a controlled service procedure; it cannot be delivered as an ordinary app-only OTA. Secure Boot and eFuse version changes are irreversible. Validate upgrade, rollback, interrupted downloads and power loss on the production board before deployment.

### Clock bootstrap

Setup supplies phone time through the authenticated BLE session. On subsequent boots ordinary SNTP supplies time, with a lower bound of 2026-01-01 and the last persisted timestamp from a successful cloud authentication. That timestamp is checkpointed at most daily. SNTP stops immediately after the initial sample; it does not periodically rewrite the clock of an established session. TLS still verifies certificate dates and never falls back to an unverified connection. **SNTP is not authenticated time**: the lower bound prevents rollback below the checkpoint, but a hostile network can still manipulate availability and time within the accepted range. A protected RTC or authenticated time service is required for a stronger time threat model. Physical BLE recovery, requiring the held setup button and the unique QR/SRP proof, can repair a poisoned future checkpoint by replacing it with current phone time. This exceptional recovery may lower the persisted bound, but never below 2026-01-01. Automatic setup without the physical action cannot lower it.

## Upgrade from protocol v2

The claim argument lists changed; deploy the server, app and firmware together for new enrollments. Existing `DEVICE_AUTH` credentials remain supported. The app permits Wi-Fi recovery for a legacy ID already owned by the signed-in account; a legacy device removed from its account needs a controlled service migration before new v3 enrollment, not silent identity regeneration. The forward-only database migration discards old unbound pending claims, adds device binding and remembers the successful enrollment claim for safe retries. A pending legacy secret is retained only for one-time recovery of a device interrupted during an old rotation; the first successful login settles the stored credential. There is no API to start another rotation.

Upgrading firmware on existing hardware needs a tested migration plan for factory provisioning data, NVS and the partition layout. Do not erase a customer's device as a routine upgrade step. Back up the database and `TOKEN_PEPPER`; changing or losing the pepper invalidates existing credentials.

## Error codes (`NACK`)

| Code | Meaning |
|---|---|
| `bad_frame` | invalid JSON / frame format |
| `frame_too_long` | line from the client > 4096 B (connection closed) |
| `unknown_command` | no such command for this port's role |
| `bad_args` | wrong number or type of arguments |
| `unauthenticated` / `already_authenticated` | wrong session state |
| `rate_limited` | too many attempts, try again later |
| `invalid_credentials` | wrong password / device secret |
| `invalid_token` | invalid session token or claim token |
| `invalid_name`, `invalid_email`, `invalid_label`, `invalid_mac`, `weak_password` | field validation |
| `account_exists` | name or e-mail taken at registration |
| `name_taken` | name taken on `CHANGE_NAME` |
| `not_found` | object does not exist or belongs to another account |
| `duplicate` | this MAC is already on the list |
| `limit_reached` | device limit (10) or target limit (64) |
| `no_device` | target is not assigned to a device |
| `device_offline` | device not connected |
| `device_unreachable` | device did not confirm in time |
| `reset_unavailable` | server has no SMTP configured, password reset disabled |
| `internal` | server error (details in the log) |
