# Wake on LAN

[Polski](README.md) | **English**

Remote Wake-on-LAN for computers from outside the local network. The phone app sends a command to the server, and the server forwards it to an ESP32 device on the home network, which broadcasts the magic packet.

```
App (Android)  --TLS:8443-->  Server (Python)  <--TLS:8444--  ESP32  --UDP magic packet-->  computer
```

The ESP32 opens the connection to the server itself, so no ports need to be opened on the home network. Only the server has to be publicly reachable.

| Directory | Contents | Technology |
|---|---|---|
| [`server/`](server/) | relay server, user accounts, database | Python 3.11+, asyncio, PostgreSQL |
| [`client/`](client/) | mobile app | Expo (React Native), TypeScript |
| [`esp_client/`](esp_client/) | firmware for the home network device | ESP-IDF, C++ |

The full description of the protocol, commands, limits and error codes is in [`server/PROTOCOL.en.md`](server/PROTOCOL.en.md).

## Requirements

- Server: Python 3.11 or newer and PostgreSQL (or Docker with Docker Compose).
- App: Node.js 20.19.4 or newer, npm, Android SDK (local builds) or an Expo account (EAS builds).
- Firmware: ESP-IDF 5.x or 6.x and an ESP32 board.
- OpenSSL to generate the TLS certificate.

Dependencies:

| Part | Dependency file | Installation |
|---|---|---|
| server (runtime) | `server/requirements.txt`, `server/pyproject.toml` | `pip install -r requirements.txt` |
| server (tests) | `server/requirements-dev.txt` | `pip install -r requirements-dev.txt` |
| app | `client/package.json`, `client/package-lock.json` | `npm ci` |
| firmware | `esp_client/components/network/idf_component.yml` | fetched automatically by `idf.py build` |

## 1. TLS certificate

All three parts use the same certificate. The app and the ESP32 pin it, so without it they will not connect to the server. The name in the certificate must match the server address (below is an example for the IP address `192.168.1.10`; for a domain use `DNS:your.domain`):

```bash
cd server
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout server.key -out server.crt \
  -subj "/CN=192.168.1.10" -addext "subjectAltName=IP:192.168.1.10"
```

Then copy the certificate (without the key):

- `server/server.crt` to `client/assets/server.pem`,
- `server/server.crt` to `esp_client/main/certs/server.crt`.

Certificate and key files are in `.gitignore`. The `server.key` key stays on the server only.

## 2. Server

### Configuration

```bash
cd server
cp .env.example .env
```

In `.env` set at least:

- `TOKEN_PEPPER`: a random string of at least 32 characters: `python -c "import secrets; print(secrets.token_urlsafe(48))"`. Changing it invalidates all sessions and paired devices.
- `DATABASE_URL`: the PostgreSQL database URL (set automatically with Docker Compose).
- `SMTP_*`: optional, used to send password reset codes. Without `SMTP_HOST` password reset is disabled.

All variables are described in [`server/.env.example`](server/.env.example).

### Running in Docker

```bash
cd server
mkdir certs
cp server.crt server.key certs/
# also set POSTGRES_PASSWORD in .env
docker compose up -d --build
```

Compose starts PostgreSQL 16 and the server on ports 8443 (app) and 8444 (ESP32).

### Running locally

```bash
cd server
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows:     .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
python -m wol_server
```

Create the database beforehand, e.g. as the `postgres` superuser:

```sql
CREATE ROLE wol LOGIN PASSWORD 'change-me';
CREATE DATABASE wol OWNER wol;
```

The server creates the database schema itself on startup.

### Tests

```bash
cd server
pip install -r requirements-dev.txt
pip install -e .
pytest
```

Tests that use PostgreSQL are skipped until you set `TEST_DATABASE_URL`, e.g. `TEST_DATABASE_URL=postgresql://wol:change-me@localhost:5432/postgres`.

## 3. Mobile app

Set the server address in [`client/app.json`](client/app.json) under `expo.extra.serverHost` and `expo.extra.serverPort` (default 8443). The certificate must be in `client/assets/server.pem` (see section 1).

```bash
cd client
npm ci
npm run android     # builds and installs a development build on a connected phone/emulator
npm start           # Metro server for an already installed development build
npm run build:apk   # installable APK via EAS Build ("preview" profile)
npm run typecheck   # TypeScript type check
```

The app is in Polish when the phone's language is Polish and in English otherwise. All texts are in [`client/src/i18n.ts`](client/src/i18n.ts).

The app uses the native module `react-native-tcp-socket`, so it does not work in Expo Go. You need a development build (`expo-dev-client`) or a built APK.

## 4. ESP32 firmware

```bash
cd esp_client
idf.py set-target esp32
idf.py menuconfig     # "Wake-on-LAN client" menu
idf.py build flash monitor
```

In the `Wake-on-LAN client` menu set:

- `WOL_WIFI_SSID`, `WOL_WIFI_PASSWORD`: the Wi-Fi network the computers to wake are on,
- `WOL_SERVER_HOST`, `WOL_SERVER_PORT`: server address and device port (default 8444). The address must match the name in the certificate,
- `WOL_CLAIM_TOKEN`: optional pairing token (see below).

**Warning:** the default configuration ([`sdkconfig.defaults`](esp_client/sdkconfig.defaults)) enables flash and NVS encryption. The first boot permanently writes the key to the chip's eFuse. The production build with Secure Boot v2 is irreversible. Before flashing for the first time, read the "Securing data on the ESP32" section in [`server/PROTOCOL.en.md`](server/PROTOCOL.en.md).

## Usage

1. Register an account in the app.
2. Pair the ESP32: on the devices tab choose "Pair device". The app shows a one-time token valid for 10 minutes. Enter it on the ESP32 serial console (`idf.py monitor`):
   ```
   claim <token>
   ```
   or compile it into `WOL_CLAIM_TOKEN` before flashing. After pairing, the device logs in by itself on every boot.
3. Add a target: the computer's MAC address (e.g. `AA:BB:CC:DD:EE:FF`) and an ESP32 device on the same network.
4. Press the wake button next to the target. The app shows success once the ESP32 confirms the magic packet was sent.

The computer must have Wake-on-LAN enabled in BIOS/UEFI and in the network adapter settings.

## Security

- All communication is encrypted with TLS (min. 1.2), and the server certificate is pinned in the app and the firmware.
- Passwords are hashed with Argon2, and session tokens and device secrets are stored in the database as an HMAC with `TOKEN_PEPPER`.
- The app stores the session token, not the password, in the system's secure storage (Keystore). If the storage cannot be read, the app goes to the login screen.
- The server limits the number of connections and login attempts, concurrent ones included. Details in [`server/PROTOCOL.en.md`](server/PROTOCOL.en.md).
- The device secret can be changed from the app (rotation). If the ESP32 does not confirm the new secret, the server disconnects it, and on reconnect whichever secret the device logs in with stays valid. A failed rotation therefore does not lock the device out.
