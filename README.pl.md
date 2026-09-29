# Wake on LAN

**Polski** | [English](README.en.md)

Zdalne budzenie komputerów (Wake-on-LAN) spoza sieci lokalnej. Aplikacja na telefonie wysyła polecenie do serwera, a serwer przekazuje je do urządzenia ESP32 w sieci domowej, które rozsyła magic packet.

```
Aplikacja (Android)  --TLS:8443-->  Serwer (Python)  <--TLS:8444--  ESP32  --UDP magic packet-->  komputer
```

ESP32 samo nawiązuje połączenie z serwerem, więc w sieci domowej nie trzeba otwierać żadnych portów. Publicznie dostępny musi być tylko serwer.

| Katalog | Zawartość | Technologia |
|---|---|---|
| [`server/`](server/) | serwer przekazujący, konta użytkowników, baza | Python 3.11+, asyncio, PostgreSQL |
| [`client/`](client/) | aplikacja mobilna | Expo (React Native), TypeScript |
| [`esp_client/`](esp_client/) | firmware urządzenia w sieci domowej | ESP-IDF, C++ |

Pełny opis protokołu, komend, limitów i kodów błędów jest w [`server/PROTOCOL.md`](server/PROTOCOL.md).

## Wymagania

- Serwer: Python 3.11 lub nowszy i PostgreSQL (albo Docker z Docker Compose).
- Aplikacja: Node.js 20.19.4 lub nowszy, npm, Android SDK (budowanie lokalne) albo konto Expo (budowanie w EAS).
- Firmware: ESP-IDF 5.x lub 6.x i płytka ESP32.
- OpenSSL do wygenerowania certyfikatu TLS.

Zależności:

| Część | Plik z zależnościami | Instalacja |
|---|---|---|
| serwer (uruchomienie) | `server/requirements.txt`, `server/pyproject.toml` | `pip install -r requirements.txt` |
| serwer (testy) | `server/requirements-dev.txt` | `pip install -r requirements-dev.txt` |
| aplikacja | `client/package.json`, `client/package-lock.json` | `npm ci` |
| firmware | `esp_client/components/network/idf_component.yml` | pobierane automatycznie przez `idf.py build` |

## 1. Certyfikat TLS

Wszystkie trzy części używają tego samego certyfikatu. Aplikacja i ESP32 przypinają go, więc bez niego nie połączą się z serwerem. Nazwa w certyfikacie musi odpowiadać adresowi serwera (poniżej przykład dla adresu IP `192.168.1.10`; dla domeny użyj `DNS:twoja.domena`):

```bash
cd server
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout server.key -out server.crt \
  -subj "/CN=192.168.1.10" -addext "subjectAltName=IP:192.168.1.10"
```

Następnie skopiuj certyfikat (bez klucza):

- `server/server.crt` do `client/assets/server.pem`,
- `server/server.crt` do `esp_client/main/certs/server.crt`.

Pliki certyfikatów i kluczy są w `.gitignore`. Klucz `server.key` zostaje tylko na serwerze.

## 2. Serwer

### Konfiguracja

```bash
cd server
cp .env.example .env
```

W `.env` ustaw co najmniej:

- `TOKEN_PEPPER`: losowy ciąg, min. 32 znaki: `python -c "import secrets; print(secrets.token_urlsafe(48))"`. Zmiana unieważnia wszystkie sesje i sparowane urządzenia.
- `DATABASE_URL`: adres bazy PostgreSQL (przy Docker Compose ustawiany automatycznie).
- `SMTP_*`: opcjonalnie, do wysyłania kodów resetu hasła. Bez `SMTP_HOST` reset hasła jest wyłączony.

Opis wszystkich zmiennych jest w [`server/.env.example`](server/.env.example).

### Uruchomienie w Dockerze

```bash
cd server
mkdir certs
cp server.crt server.key certs/
# w .env ustaw też POSTGRES_PASSWORD
docker compose up -d --build
```

Compose uruchamia PostgreSQL 16 i serwer na portach 8443 (aplikacja) i 8444 (ESP32).

### Uruchomienie lokalne

```bash
cd server
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows:     .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
python -m wol_server
```

Wcześniej utwórz bazę, np. jako superużytkownik `postgres`:

```sql
CREATE ROLE wol LOGIN PASSWORD 'change-me';
CREATE DATABASE wol OWNER wol;
```

Schemat bazy serwer tworzy sam przy starcie.

### Testy

```bash
cd server
pip install -r requirements-dev.txt
pip install -e .
pytest
```

Testy korzystające z PostgreSQL są pomijane, dopóki nie ustawisz `TEST_DATABASE_URL`, np. `TEST_DATABASE_URL=postgresql://wol:change-me@localhost:5432/postgres`.

## 3. Aplikacja mobilna

Adres serwera ustaw w [`client/app.json`](client/app.json) w `expo.extra.serverHost` i `expo.extra.serverPort` (domyślnie 8443). Certyfikat musi leżeć w `client/assets/server.pem` (patrz punkt 1).

```bash
cd client
npm ci
npm run android     # buduje i instaluje wersję deweloperską na podłączonym telefonie/emulatorze
npm start           # serwer Metro dla już zainstalowanej wersji deweloperskiej
npm run build:apk   # APK do instalacji przez EAS Build (profil "preview")
npm run typecheck   # sprawdzenie typów TypeScript
```

Aplikacja jest po polsku, gdy telefon ma ustawiony język polski, a w przeciwnym razie po angielsku. Wszystkie teksty są w [`client/src/i18n.ts`](client/src/i18n.ts).

Aplikacja używa natywnego modułu `react-native-tcp-socket`, więc nie działa w Expo Go. Potrzebna jest wersja deweloperska (`expo-dev-client`) albo zbudowany APK.

## 4. Firmware ESP32

```bash
cd esp_client
idf.py set-target esp32
idf.py menuconfig     # menu "Wake-on-LAN client"
idf.py build flash monitor
```

W menu `Wake-on-LAN client` ustaw:

- `WOL_WIFI_SSID`, `WOL_WIFI_PASSWORD`: sieć Wi-Fi, w której są budzone komputery,
- `WOL_SERVER_HOST`, `WOL_SERVER_PORT`: adres serwera i port urządzeń (domyślnie 8444). Adres musi zgadzać się z nazwą w certyfikacie,
- `WOL_CLAIM_TOKEN`: opcjonalnie, token parowania (patrz niżej).

**Uwaga:** domyślna konfiguracja ([`sdkconfig.defaults`](esp_client/sdkconfig.defaults)) włącza szyfrowanie flasha i NVS. Pierwsze uruchomienie trwale zapisuje klucz w eFuse układu. Wersja produkcyjna z Secure Boot v2 jest nieodwracalna. Przed pierwszym flashowaniem przeczytaj sekcję „Zabezpieczenie danych na ESP32” w [`server/PROTOCOL.md`](server/PROTOCOL.md).

## Użytkowanie

1. Zarejestruj konto w aplikacji.
2. Parowanie ESP32: w zakładce urządzeń wybierz „Sparuj urządzenie”. Aplikacja pokaże jednorazowy token ważny 10 minut. Wpisz go na konsoli szeregowej ESP32 (`idf.py monitor`):
   ```
   claim <token>
   ```
   albo wkompiluj go w `WOL_CLAIM_TOKEN` przed flashowaniem. Po sparowaniu urządzenie loguje się samo przy każdym starcie.
3. Dodaj cel: adres MAC komputera (np. `AA:BB:CC:DD:EE:FF`) i urządzenie ESP32 w tej samej sieci.
4. Naciśnij przycisk budzenia przy celu. Aplikacja pokaże sukces, gdy ESP32 potwierdzi wysłanie magic packetu.

Komputer musi mieć włączone Wake-on-LAN w BIOS/UEFI i w ustawieniach karty sieciowej.

## Bezpieczeństwo

- Całą komunikację szyfruje TLS (min. 1.2), a certyfikat serwera jest przypięty w aplikacji i firmware.
- Hasła są haszowane Argon2, a tokeny sesji i sekrety urządzeń są w bazie przechowywane jako HMAC z `TOKEN_PEPPER`.
- Aplikacja przechowuje token sesji w bezpiecznym magazynie systemu (Keystore), a nie hasło. Jeśli magazynu nie da się odczytać, aplikacja przechodzi do ekranu logowania.
- Serwer ogranicza liczbę połączeń i prób logowania, także równoległych. Szczegóły w [`server/PROTOCOL.md`](server/PROTOCOL.md).
- Sekret urządzenia można zmienić z aplikacji (rotacja). Jeśli ESP32 nie potwierdzi nowego sekretu, serwer je rozłącza, a przy ponownym połączeniu obowiązuje ten sekret, którym urządzenie się zaloguje. Nieudana rotacja nie odcina więc urządzenia.
