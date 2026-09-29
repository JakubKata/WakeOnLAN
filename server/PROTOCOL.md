# WoL server protocol (v2)

[Polski](PROTOCOL.md) | **English**

Two TLS ports (min. TLS 1.2), both using the same server certificate:

- `CLIENT_PORT` (default 8443): mobile/desktop app,
- `DEVICE_PORT` (default 8444): ESP32 devices.

The client and the ESP must verify the server certificate (a pinned certificate or a custom CA embedded in the firmware/app). Without that, TLS does not protect against MITM.

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

## Device pairing (claim token)

```
App    -> Server : LOGIN / RESUME
App    -> Server : CREATE_CLAIM "Desk"           -> ACK [claim_token, 600]
User   -> ESP    : claim_token via the serial console ("claim <token>")
                   or in the firmware (Kconfig WOL_CLAIM_TOKEN, Wi-Fi: WOL_WIFI_SSID/PASSWORD)
ESP    -> Server : DEVICE_CLAIM claim_token      -> ACK [device_id, device_secret]
ESP              : stores device_id and device_secret in (encrypted) NVS
```

- There is no BLE or SoftAP provisioning. Wi-Fi and the server address are compiled into the firmware. The claim token can be set in Kconfig at the first flash, or later, without reflashing, on the UART console with the `claim <token>` command. The token from the console takes precedence.
- The ESP remembers the last token that was consumed or rejected by the server and never sends it again. Without credentials and without a new token it does not connect to the server and just waits for the `claim` command.
- The claim token is 128 bits, single-use, valid for 10 minutes and bound to the account. A new `CREATE_CLAIM` invalidates the previous one. `CHANGE_PASSWORD`, `RESET_PASSWORD` and `LOGOUT_ALL` invalidate an unused claim.
- After `DEVICE_CLAIM` the connection is authenticated immediately.
- Every subsequent ESP connection starts with `DEVICE_AUTH device_id device_secret`.
- A new connection with the same `device_id` closes the previous one.

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
| `CREATE_CLAIM` | device_name | claim_token, ttl_seconds |
| `LIST_DEVICES` | (none) | `[{id, name, online, last_seen_at}]` |
| `RENAME_DEVICE` | device_id, name | device_id, name |
| `REMOVE_DEVICE` | device_id | device_id; the ESP receives `UNPAIRED` |
| `ROTATE_DEVICE_SECRET` | device_id | device_id (the device must be online; concurrent rotations are executed one after another; without confirmation from the ESP `device_unreachable`, and the server disconnects the ESP) |
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
| `DEVICE_CLAIM` | claim_token | `ACK [device_id, device_secret]` |
| `DEVICE_AUTH` | device_id, device_secret | `ACK []`; a wrong or malformed secret gives `NACK invalid_credentials` |
| `PING` | (none) | `PONG` (only after authentication) |
| `PONG` | (none) | no response |
| `WAKE_ACK` | request_id | no response |
| `SECRET_ACK` | request_id | no response |

Server -> ESP:

| Command | Arguments | Expected ESP reaction |
|---|---|---|
| `PING` | (none) | `PONG` |
| `WAKE_UP` | request_id, mac | send the magic packet, then `WAKE_ACK request_id` |
| `SET_SECRET` | request_id, new_secret | store in NVS, then `SECRET_ACK request_id` |
| `UNPAIRED` | (none) | erase data from NVS and wait for a new claim token from the console |

- The server sends `PING` when nothing has arrived for 30 s, and disconnects after 90 s of silence.
- `WAKE_UP` on the client side ends with `NACK device_unreachable` if `WAKE_ACK` does not arrive within 5 s.
- After `SET_SECRET` the old secret keeps working until the ESP confirms the new one or logs in with it.
- If `SECRET_ACK` does not arrive within 5 s, the server disconnects the ESP. Whichever secret the ESP logs in with next (old or new) becomes the only valid one.
- The ESP never responds to `ACK`/`NACK`, to avoid a loop.
- The ESP should use cJSON (the `json` component in ESP-IDF) instead of a hand-written parser. Frames nested deeper than 4 levels are rejected before parsing, because a recursive parser could overflow the task stack.
- Socket writes have a 10 s deadline. If the server stops receiving data, the ESP closes the connection and reconnects.

### Securing data on the ESP32

`device_secret` is enough to impersonate the device, so flash and NVS must be encrypted:

- [esp_client/sdkconfig.defaults](../esp_client/sdkconfig.defaults) enables flash encryption (Development mode, flashing over UART is still possible) and NVS encryption. The NVS keys live in the encrypted `nvs_keys` partition ([partitions.csv](../esp_client/partitions.csv)) and are generated on first boot.
- Production build: `idf.py -B build-release -D SDKCONFIG=sdkconfig.release -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.release" build`. The separate `sdkconfig.release` file is required because ESP-IDF reads `SDKCONFIG_DEFAULTS` only when it creates a new `sdkconfig`; an existing `sdkconfig` from a development build would silently override the release profile. The [sdkconfig.defaults.release](../esp_client/sdkconfig.defaults.release) profile switches encryption to Release mode and enables Secure Boot v2. You must generate a signing key beforehand: `espsecure.py generate_signing_key --version 2 secure_boot_signing_key.pem`. Keep it outside the repository, because without it you can no longer flash new firmware.
- Even Development mode writes the encryption key to eFuse on first boot. It can then be disabled only a limited number of times (three on the ESP32). Release mode and Secure Boot v2 are completely irreversible. Secure Boot v2 on a plain ESP32 requires chip revision 3.0 or newer.
- Changing the partition table requires a one-time `idf.py erase-flash` on devices with the previous firmware, followed by re-pairing.

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
