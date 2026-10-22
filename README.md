# Wake on LAN

[Polski](README.pl.md) | **English**

Remote Wake-on-LAN for computers outside the local network. The phone sends a command to the server, which forwards it to an ESP32 on the home network. The ESP32 broadcasts the magic packet. It opens the outbound server connection itself; the home router needs no port forwarding.

The relay keeps its own JSON-lines protocol over TCP/TLS and Python `asyncio`. BLE is used for local provisioning; no Redis, RabbitMQ or MQTT broker is required.

The customer plugs in the device, signs in to the Android app, scans the device's unique QR label and selects their home Wi-Fi. The app provisions the device over authenticated, encrypted BLE and automatically binds it to the account. There is no serial-console setup or manual device-secret control.

| Connection | Purpose |
|---|---|
| Android → server, TLS 8443 | Account, devices, wake requests |
| ESP32 → server, TLS 8444 | Authentication, wake commands and acknowledgements |
| Android ↔ ESP32, BLE | Local setup using Espressif Security 2 |
| ESP32 → computer, UDP | Wake-on-LAN magic packet |

| Directory | Contents | Technology |
|---|---|---|
| [`server/`](server/) | Relay, accounts, database, ACME deployment | Python 3.11+, asyncio, PostgreSQL |
| [`client/`](client/) | Android app and native BLE provisioning module | Expo, React Native, TypeScript, Kotlin |
| [`esp_client/`](esp_client/) | Device firmware and manufacturing configuration | ESP-IDF, C++ |

The complete commands, limits, enrollment rules and error codes are in [`server/PROTOCOL.md`](server/PROTOCOL.md). The detailed code guide is in [`docs/documentation_en.html`](docs/documentation_en.html).

## Requirements

- Server: Python 3.11+ and PostgreSQL, or Docker with Docker Compose.
- A public DNS name pointing to the server. For the included ACME deployment, inbound TCP 80 must be available for HTTP-01 validation; clients use TCP 8443 and 8444.
- App: Node.js 20.19.4+, npm and Android SDK, or EAS Build. A physical Android phone is needed for BLE acceptance tests.
- Firmware: ESP-IDF 5.5.1 and a BLE-capable ESP32 board with at least 4 MB flash and a physical setup button. The per-device provisioning data must be prepared during manufacturing.

| Part | Dependency files | Installation |
|---|---|---|
| Server runtime | `server/requirements.txt`, `server/pyproject.toml` | `pip install -r requirements.txt` |
| Server tests | `server/requirements-dev.txt` | `pip install -r requirements-dev.txt` |
| App | `client/package.json`, `client/package-lock.json` | `npm ci` |
| Firmware | `esp_client/components/network/idf_component.yml` | Fetched by `idf.py build` |

## 1. TLS certificate lifecycle

Use a certificate from a public CA trusted by Android and the ESP-IDF root certificate bundle. Set the same DNS hostname in the server certificate configuration, app configuration and firmware. Clients verify the chain, hostname and certificate validity; the server's leaf certificate is not copied into the app or firmware.

The included Compose deployment obtains and renews the certificate through ACME automatically. It publishes the validated certificate chain and private key atomically to a restricted runtime volume. The server checks for updates every `TLS_RELOAD_INTERVAL` seconds (default 60), validates the replacement and uses a new TLS context for new connections. Existing connections remain open. An invalid replacement is rejected and logged; the previously loaded context stays active. The ACME publisher and server also validate the full WebPKI path against their platform CA stores, so keep the deployment images and their trust stores updated.

Routine certificate renewal therefore needs no customer action, app release or firmware flash. Root CA changes are different: keep the firmware trust bundle maintained, introduce replacement roots before switching the server chain, and plan recovery for devices that have been offline for a long time. Do not disable verification to work around expired certificates or a bad clock.

Monitor ACME health, renewal failures and the server's expiry warnings. Automatic renewal still depends on DNS, network reachability and a functioning host. A certificate that really expires must be rejected.

## 2. Server

### Configuration

```bash
cd server
cp .env.example .env
```

Set at least:

- `TLS_SERVER_NAME`: the public DNS name, e.g. `wol.example.com`, matching the certificate's DNS SAN.
- `ACME_EMAIL`: contact address for the ACME account.
- `TOKEN_PEPPER`: a random secret of at least 32 characters, e.g. `python -c "import secrets; print(secrets.token_urlsafe(48))"`. Back it up securely; changing it invalidates sessions and device credentials.
- `POSTGRES_PASSWORD`: password for the bundled database. Follow the URL-safe character restriction in `.env.example`.
- `SMTP_*`: optional password-reset delivery. Without `SMTP_HOST`, password reset is disabled.

All variables are described in [`server/.env.example`](server/.env.example).

### Docker deployment

Point the domain's A/AAAA records at this host, open TCP 80, 8443 and 8444, then run:

```bash
docker compose up -d --build
docker compose ps
docker compose logs acme server
```

Compose starts PostgreSQL 16, obtains the initial certificate and starts the server after the ACME runtime is healthy. The ACME service checks renewal about every 12 hours with jitter and retries failures. Only the ACME service receives the `acme-state` volume; the application receives the runtime certificate volume read-only. Back up the database, ACME state and pepper securely.

To test renewal against the CA's staging service:

```bash
docker compose exec acme certbot renew --cert-name wol --dry-run
```

Do not add `--run-deploy-hooks` to that staging check. The included service uses standalone HTTP-01 and needs port 80 free. If another web server owns that port, configure a managed webroot or DNS-01 ACME deployment separately and provide its certificate files to the application.

### Running locally

Use an externally managed ACME certificate and set `TLS_CERT_FILE` to its full chain and `TLS_KEY_FILE` to its private key. Keep renewal symlinks intact; do not copy a one-off certificate into the repository. Set `DATABASE_URL` for your PostgreSQL instance.

```bash
cd server
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows:     .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
python -m wol_server
```

Create the database first, e.g. as the `postgres` superuser:

```sql
CREATE ROLE wol LOGIN PASSWORD 'change-me';
CREATE DATABASE wol OWNER wol;
```

The server applies forward-only schema migrations on startup. Protocol v3 invalidates unused v2 claims but retains existing device authentication credentials and one-time recovery for credentials left pending by the old implementation. See the protocol's upgrade section before updating an existing deployment.

### Tests

```bash
cd server
pip install -r requirements-dev.txt
pip install -e .
pytest
```

Set `TEST_DATABASE_URL` to a dedicated test PostgreSQL database to run the database and integration suites, e.g. `postgresql://wol:change-me@localhost:5432/postgres`. Without it, those tests are skipped. TLS tests use isolated test certificates; this is not the production certificate provisioning path. The [CI workflow](.github/workflows/ci.yml) defines PostgreSQL integration tests, Android compilation and ESP-IDF builds; a configured workflow is not evidence that it has run successfully.

## 3. Android app

Set `expo.extra.serverHost` in [`client/app.json`](client/app.json) to the public DNS name, and `serverPort` to the client port (default 8443).

```bash
cd client
npm ci
npm run android     # native development build on a connected phone/emulator
npm start           # Metro for an installed development build
npm run build:apk   # APK through EAS Build, preview profile
npm run typecheck
```

The app uses native TLS and BLE provisioning modules, so Expo Go is not supported. The included `patch-package` patch for the pinned `react-native-tcp-socket` version enforces Android hostname verification and TLS 1.2+. Keep the patch and the mandatory `postinstall` check; do not build for production with `npm --ignore-scripts`.

Grant camera and nearby Bluetooth permissions when prompted. On Android versions that require location permission for BLE scanning, grant it for setup. The app is Polish when the phone uses Polish and English otherwise; texts are in [`client/src/i18n.ts`](client/src/i18n.ts).

## 4. ESP32 firmware and manufacturing

The device needs unique manufacturing provisioning data before delivery. Generate a different SRP username/password and salt/verifier for each unit, provision its encrypted NVS data and attach the corresponding QR label. The QR password authorizes local configuration; protect it like a device credential. Never ship a shared example password or log QR contents. The customer does not generate certificates or flash credentials.

```bash
cd esp_client
idf.py set-target esp32
idf.py menuconfig     # Wake-on-LAN client
idf.py build
```

Set the product's public `WOL_SERVER_HOST`, device port `WOL_SERVER_PORT` (default 8444) and the setup-button GPIO for the actual board. Wi-Fi credentials and cloud claim tokens are supplied through BLE; they are not build settings. Firmware uses the ESP-IDF certificate bundle rather than a server certificate asset.

### Per-unit factory files

In the activated ESP-IDF 5.5.1 Python environment, before the unit's first boot:

```bash
# From esp_client/; use a new, private output directory for every physical unit.
pip install -r tools/requirements.txt
python tools/provision_factory.py --output /secure/manufacturing/unit-001
```

The tool uses Espressif's SRP implementation and writes `label.json`, printable `label.svg`, the salt/verifier `factory.csv`, encrypted `nvs.bin` and `keys/nvs_keys.bin`. Keep the directory private and never reuse a unit's files. The QR carries the username/password; firmware stores the salt/verifier, not the plaintext QR password.

After building and checking the board-specific configuration, flash all images and both per-unit NVS files in one operation without automatically booting midway:

```bash
cd build
python -m esptool --chip esp32 --port PORT --after no_reset write_flash @flash_args \
  0x11000 /secure/manufacturing/unit-001/nvs.bin \
  0x17000 /secure/manufacturing/unit-001/keys/nvs_keys.bin
```

Replace `PORT` with the actual serial port and reset manually only after the complete operation succeeds. The offsets match this repository's partition table. This is the **new-unit** manufacturing path; previously encrypted or released chips require a dedicated service procedure. Do not overwrite an existing unit's NVS or encryption keys.

### Signed updates

Use the release profile with Secure Boot, anti-rollback and `WOL_ENABLE_OTA`. Configure `WOL_FIRMWARE_URL` to a fixed HTTPS image URL for this product and target; it must not be left empty for production. Each image must be signed by the retained signing key, keep the same project name, and have a strictly increasing numeric `PROJECT_VER` (`major.minor.patch`, initial value `2.0.0`). Set the secure version according to the anti-rollback release policy.

The fixed URL must serve the image directly with HTTP 200 and `Content-Length`, without redirects or chunked transfer. A stable image checks approximately daily independently of relay authentication, so a still-trusted update host can recover a relay trust failure. It writes the inactive OTA slot and confirms new firmware only after cloud authentication. Without confirmation within 120 seconds it rolls back. Signed firmware carries trust-bundle updates; deploy new roots before changing server trust chains. The previous single-app partition layout needs a controlled service migration before this OTA path can be used. See the [update and clock sections](server/PROTOCOL.md#firmware-updates-and-trust-store-maintenance) for recovery boundaries and the unauthenticated-SNTP limitation.

**Hardware security:** [`sdkconfig.defaults`](esp_client/sdkconfig.defaults) enables flash and NVS encryption. The first boot writes encryption state to eFuse. The release profile enables Secure Boot v2 and is irreversible. Prepare and retain the signing key outside the repository, verify board revision and partition layout, and read [ESP32 data protection](server/PROTOCOL.md#securing-data-on-the-esp32) before flashing. An existing customer's flash must not be erased as a routine migration step.

## Usage

1. Plug in the provisioned device and sign in to the Android app.
2. Choose pairing, scan the unit's QR label and let the app find and authenticate it over BLE.
3. Name the device, select a compatible 2.4 GHz WPA2/WPA3 Personal Wi-Fi network and enter its password. Wait for confirmation that the device is online on your account.
4. Add a target with the computer's MAC address and the device on the same network.
5. Press wake. Success means the ESP32 acknowledged sending the magic packet; the computer must also have Wake-on-LAN enabled in BIOS/UEFI and its network adapter.

On an unpaired unit, boot opens a ten-minute BLE setup window. For Wi-Fi recovery on a paired unit, hold the dedicated active-low setup button for three seconds during power-on (default GPIO 4; verify your board) and use the same QR credential. Changing Wi-Fi preserves the device identity and account owner. Transfer to another account requires the previous owner to remove the device first. Network loss and failed authentication do not reset ownership. Five failed local authentication attempts close the setup window. Devices with legacy pre-v3 IDs can recover Wi-Fi while owned by the signed-in account; re-enrolling a removed legacy identity requires service migration.

## Security and release validation

- TLS validates chain, hostname and dates on both clients; BLE setup uses SRP6a and AES-GCM.
- The ESP32 persists its random 256-bit device secret before enrollment. Its ID is derived from the secret; account-bound claims cannot replace an existing owner. Interrupted enrollment can resume with the saved credentials.
- The database stores token and device-secret HMACs using `TOKEN_PEPPER`; account passwords use Argon2. The app stores its session token in Android secure storage, not the account password.
- Wi-Fi passwords travel only through the authenticated local setup channel. The app does not expose cloud claim tokens or manual secret controls.
- Test real hardware before release: wrong QR/password, Wi-Fi errors, permission denial, power loss during setup, lost claim acknowledgements, offline recovery, certificate renewal and rejection of invalid/expired/wrong-host certificates. Passing server tests or TypeScript checks does not replace a native Android build and ESP32 acceptance tests.
