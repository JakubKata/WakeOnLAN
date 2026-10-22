# Wake on LAN

**Polski** | [English](README.md)

Zdalne budzenie komputerów (Wake-on-LAN) spoza sieci lokalnej. Telefon wysyła polecenie do serwera, a ten przekazuje je do ESP32 w sieci domowej. ESP32 rozsyła magic packet i samo otwiera połączenie wychodzące do serwera; domowy router nie wymaga przekierowania portów.

Serwer zachowuje własny protokół JSON-lines przez TCP/TLS i Python `asyncio`. BLE służy lokalnej konfiguracji; Redis, RabbitMQ ani broker MQTT nie są wymagane.

Klient podłącza urządzenie do prądu, loguje się w aplikacji Android, skanuje unikalną etykietę QR urządzenia i wybiera domowe Wi-Fi. Aplikacja konfiguruje urządzenie przez uwierzytelnione, szyfrowane BLE i automatycznie przypisuje je do konta. Nie ma konfiguracji przez konsolę szeregową ani ręcznego zarządzania sekretem urządzenia.

| Połączenie | Przeznaczenie |
|---|---|
| Android → serwer, TLS 8443 | Konto, urządzenia, polecenia budzenia |
| ESP32 → serwer, TLS 8444 | Logowanie, polecenia budzenia i potwierdzenia |
| Android ↔ ESP32, BLE | Lokalna konfiguracja przez Espressif Security 2 |
| ESP32 → komputer, UDP | Magic packet Wake-on-LAN |

| Katalog | Zawartość | Technologia |
|---|---|---|
| [`server/`](server/) | Serwer przekazujący, konta, baza, wdrożenie ACME | Python 3.11+, asyncio, PostgreSQL |
| [`client/`](client/) | Aplikacja Android i natywny moduł konfiguracji BLE | Expo, React Native, TypeScript, Kotlin |
| [`esp_client/`](esp_client/) | Firmware i konfiguracja produkcyjna urządzeń | ESP-IDF, C++ |

Pełny opis komend, limitów, reguł parowania i błędów jest w [`server/PROTOCOL.pl.md`](server/PROTOCOL.pl.md). Szczegółowy przewodnik po kodzie: [`docs/dokumentacja_pl.html`](docs/dokumentacja_pl.html).

## Wymagania

- Serwer: Python 3.11+ i PostgreSQL albo Docker z Docker Compose.
- Publiczna nazwa DNS wskazująca serwer. Dołączone wdrożenie ACME wymaga dostępnego portu TCP 80 dla walidacji HTTP-01; klienci używają TCP 8443 i 8444.
- Aplikacja: Node.js 20.19.4+, npm i Android SDK albo EAS Build. Testy odbiorcze BLE wymagają fizycznego telefonu Android.
- Firmware: ESP-IDF 5.5.1 i płytka ESP32 obsługująca BLE, z co najmniej 4 MB flash i fizycznym przyciskiem konfiguracji. Dane konfiguracji każdego egzemplarza trzeba przygotować w produkcji.

| Część | Pliki zależności | Instalacja |
|---|---|---|
| Serwer | `server/requirements.txt`, `server/pyproject.toml` | `pip install -r requirements.txt` |
| Testy serwera | `server/requirements-dev.txt` | `pip install -r requirements-dev.txt` |
| Aplikacja | `client/package.json`, `client/package-lock.json` | `npm ci` |
| Firmware | `esp_client/components/network/idf_component.yml` | Pobierane przez `idf.py build` |

## 1. Cykl życia certyfikatu TLS

Użyj certyfikatu publicznego CA zaufanego przez Androida i pakiet głównych CA ESP-IDF. Ustaw tę samą nazwę DNS w konfiguracji certyfikatu serwera, aplikacji i firmware. Klienci sprawdzają łańcuch, nazwę hosta i ważność; certyfikat końcowy serwera nie jest kopiowany do aplikacji ani firmware.

Dołączone wdrożenie Compose automatycznie uzyskuje i odnawia certyfikat przez ACME. Publikuje zweryfikowany łańcuch i klucz prywatny atomowo w wolumenie z ograniczonym dostępem. Serwer sprawdza aktualizacje co `TLS_RELOAD_INTERVAL` sekund (domyślnie 60), weryfikuje nowe pliki i używa nowego kontekstu TLS dla nowych połączeń. Istniejące połączenia pozostają otwarte. Niepoprawny zamiennik zostaje odrzucony i zapisany w logu; poprzedni kontekst pozostaje aktywny. Publikator ACME i serwer sprawdzają także pełną ścieżkę WebPKI wobec systemowych magazynów CA, dlatego utrzymuj aktualne obrazy wdrożenia i ich magazyny zaufania.

Zwykłe odnowienie nie wymaga działania klienta, nowej aplikacji ani flashowania. Zmiana głównego CA jest osobną operacją: utrzymuj aktualny pakiet zaufania firmware, dostarczaj nowe korzenie przed zmianą łańcucha serwera i zaplanuj odzyskanie urządzeń długo pozostających offline. Nie wyłączaj weryfikacji, aby obejść wygasły certyfikat albo błędny zegar.

Monitoruj stan ACME, nieudane odnowienia i ostrzeżenia serwera o wygaśnięciu. Automatyzacja nadal zależy od DNS, dostępności sieci i sprawności hosta. Certyfikat, który rzeczywiście wygasł, musi zostać odrzucony.

## 2. Serwer

### Konfiguracja

```bash
cd server
cp .env.example .env
```

Ustaw co najmniej:

- `TLS_SERVER_NAME`: publiczna nazwa DNS, np. `wol.example.com`, zgodna z DNS SAN certyfikatu.
- `ACME_EMAIL`: adres kontaktowy konta ACME.
- `TOKEN_PEPPER`: losowy sekret o długości co najmniej 32 znaków, np. `python -c "import secrets; print(secrets.token_urlsafe(48))"`. Zachowaj bezpieczną kopię; zmiana unieważnia sesje i dane logowania urządzeń.
- `POSTGRES_PASSWORD`: hasło dołączonej bazy. Przestrzegaj ograniczenia znaków bezpiecznych w URL opisanego w `.env.example`.
- `SMTP_*`: opcjonalna wysyłka kodów resetu hasła. Bez `SMTP_HOST` reset jest wyłączony.

Wszystkie zmienne opisuje [`server/.env.example`](server/.env.example).

### Wdrożenie Docker

Skieruj rekordy A/AAAA domeny na ten host, udostępnij TCP 80, 8443 i 8444, następnie uruchom:

```bash
docker compose up -d --build
docker compose ps
docker compose logs acme server
```

Compose uruchamia PostgreSQL 16, uzyskuje pierwszy certyfikat i startuje serwer po poprawnym przygotowaniu ACME. Usługa ACME sprawdza odnowienie mniej więcej co 12 godzin z losowym przesunięciem i ponawia nieudane próby. Tylko ACME ma dostęp do wolumenu `acme-state`; aplikacja otrzymuje wolumen certyfikatu roboczego tylko do odczytu. Wykonuj bezpieczne kopie bazy, stanu ACME i peppera.

Sprawdzenie odnowienia na środowisku testowym CA:

```bash
docker compose exec acme certbot renew --cert-name wol --dry-run
```

Do testu nie dodawaj `--run-deploy-hooks`. Dołączona usługa używa standalone HTTP-01 i wymaga wolnego portu 80. Jeśli zajmuje go inny serwer WWW, skonfiguruj osobno zarządzane ACME z webroot albo DNS-01 i przekaż aplikacji jego pliki certyfikatu.

### Uruchomienie lokalne

Użyj certyfikatu zarządzanego zewnętrznie przez ACME. Ustaw `TLS_CERT_FILE` na pełny łańcuch i `TLS_KEY_FILE` na klucz prywatny. Zachowaj dowiązania używane przy odnawianiu; nie kopiuj jednorazowego certyfikatu do repozytorium. Ustaw `DATABASE_URL` swojej bazy PostgreSQL.

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

Serwer przy starcie stosuje migracje schematu wyłącznie do przodu. Protokół v3 unieważnia niewykorzystane claimy v2, ale zachowuje istniejące dane logowania urządzeń i jednorazowe odzyskanie danych pozostawionych w stanie oczekiwania przez stary mechanizm. Przed aktualizacją działającego wdrożenia przeczytaj sekcję migracji w protokole.

### Testy

```bash
cd server
pip install -r requirements-dev.txt
pip install -e .
pytest
```

Ustaw `TEST_DATABASE_URL` na osobną testową bazę PostgreSQL, aby uruchomić testy bazy i integracji, np. `postgresql://wol:change-me@localhost:5432/postgres`. Bez tej zmiennej są pomijane. Testy TLS używają odizolowanych certyfikatów testowych; nie jest to ścieżka dostarczania certyfikatów produkcyjnych.

## 3. Aplikacja Android

W [`client/app.json`](client/app.json) ustaw `expo.extra.serverHost` na publiczną nazwę DNS, a `serverPort` na port klienta (domyślnie 8443).

```bash
cd client
npm ci
npm run android     # natywny build deweloperski na podłączonym telefonie/emulatorze
npm start           # Metro dla zainstalowanego buildu deweloperskiego
npm run build:apk   # APK przez EAS Build, profil preview
npm run typecheck
```

Aplikacja używa natywnego TLS i konfiguracji BLE, więc nie działa w Expo Go. Dołączona poprawka `patch-package` dla przypiętej wersji `react-native-tcp-socket` wymusza kontrolę nazwy hosta na Androidzie i TLS 1.2+. Zachowaj poprawkę oraz obowiązkowy krok `postinstall`; nie buduj wersji produkcyjnej z `npm --ignore-scripts`.

Nadaj uprawnienia aparatu i pobliskich urządzeń Bluetooth, gdy poprosi o nie aplikacja. W wersjach Androida wymagających lokalizacji do skanowania BLE nadaj ją na potrzeby konfiguracji. Aplikacja jest po polsku, gdy telefon używa polskiego, w przeciwnym razie po angielsku; teksty są w [`client/src/i18n.ts`](client/src/i18n.ts).

## 4. Firmware ESP32 i produkcja

Przed dostarczeniem urządzenie wymaga unikalnych danych produkcyjnych. Dla każdego egzemplarza wygeneruj inną nazwę użytkownika/hasło SRP oraz sól i weryfikator, zapisz szyfrowane dane NVS i dołącz odpowiadającą im etykietę QR. Hasło QR uprawnia do lokalnej konfiguracji; chroń je jak dane dostępowe urządzenia. Nie dostarczaj wspólnego hasła przykładowego i nie loguj zawartości QR. Klient nie generuje certyfikatów ani nie flashuje danych logowania.

```bash
cd esp_client
idf.py set-target esp32
idf.py menuconfig     # Wake-on-LAN client
idf.py build
```

Ustaw publiczny `WOL_SERVER_HOST` produktu, port urządzeń `WOL_SERVER_PORT` (domyślnie 8444) oraz GPIO przycisku konfiguracji zgodne z płytką. Dane Wi-Fi i token claim konta są dostarczane przez BLE; nie są ustawieniami kompilacji. Firmware używa pakietu CA ESP-IDF zamiast pliku certyfikatu serwera.

### Pliki fabryczne egzemplarza

W aktywowanym środowisku Python ESP-IDF 5.5.1, przed pierwszym uruchomieniem egzemplarza:

```bash
# Z esp_client/; nowy prywatny katalog wynikowy dla każdego fizycznego egzemplarza.
pip install -r tools/requirements.txt
python tools/provision_factory.py --output /secure/manufacturing/unit-001
```

Narzędzie używa implementacji SRP Espressif i zapisuje `label.json`, etykietę `label.svg`, sól/weryfikator w `factory.csv`, szyfrowany `nvs.bin` oraz `keys/nvs_keys.bin`. Zachowaj prywatność katalogu i nigdy nie używaj plików jednego egzemplarza ponownie. QR zawiera nazwę użytkownika/hasło; firmware przechowuje sól/weryfikator, a nie jawne hasło QR.

Po zbudowaniu i sprawdzeniu konfiguracji płytki wgraj wszystkie obrazy oraz oba pliki NVS w jednej operacji, bez automatycznego uruchomienia pośredniego:

```bash
cd build
python -m esptool --chip esp32 --port PORT --after no_reset write_flash @flash_args \
  0x11000 /secure/manufacturing/unit-001/nvs.bin \
  0x17000 /secure/manufacturing/unit-001/keys/nvs_keys.bin
```

Zastąp `PORT` właściwym portem szeregowym i zresetuj urządzenie ręcznie dopiero po sukcesie całej operacji. Adresy odpowiadają tablicy partycji tego repozytorium. To ścieżka produkcji **nowego egzemplarza**; układy wcześniej zaszyfrowane lub wydane wymagają osobnej procedury serwisowej. Nie nadpisuj NVS ani kluczy szyfrowania istniejącego urządzenia.

### Podpisane aktualizacje

Użyj profilu release z Secure Boot, anti-rollback i `WOL_ENABLE_OTA`. Ustaw `WOL_FIRMWARE_URL` na stały URL obrazu HTTPS dla tego produktu i układu; w produkcji nie może pozostać pusty. Każdy obraz musi być podpisany zachowanym kluczem, mieć tę samą nazwę projektu oraz ściśle rosnący numeryczny `PROJECT_VER` (`major.minor.patch`, początkowo `2.0.0`). Ustaw secure version zgodnie z polityką anti-rollback wydania.

Stały URL musi zwracać obraz bezpośrednio przez HTTP 200 i `Content-Length`, bez przekierowań i transferu chunked. Stabilny obraz sprawdza aktualizacje mniej więcej codziennie niezależnie od logowania do serwera, więc nadal zaufany host aktualizacji może naprawić problem z zaufaniem serwera. Urządzenie zapisuje nieaktywny slot OTA i zatwierdza nowe firmware dopiero po logowaniu do chmury. Brak potwierdzenia przez 120 sekund powoduje rollback. Podpisane firmware dostarcza aktualizacje pakietu zaufania; nowe główne CA należy dostarczyć przed zmianą łańcuchów serwera. Poprzedni układ partycji z jedną aplikacją wymaga kontrolowanej migracji serwisowej przed użyciem tej ścieżki OTA. Granice odzyskiwania i ograniczenie nieuwierzytelnionego SNTP opisują [sekcje aktualizacji oraz zegara](server/PROTOCOL.pl.md#aktualizacje-firmware-i-magazynu-zaufania).

**Zabezpieczenie sprzętu:** [`sdkconfig.defaults`](esp_client/sdkconfig.defaults) włącza szyfrowanie flash i NVS. Pierwszy start zapisuje stan szyfrowania w eFuse. Profil release włącza Secure Boot v2 i jest nieodwracalny. Przygotuj i zachowaj klucz podpisu poza repozytorium, sprawdź rewizję układu oraz partycje i przed flashowaniem przeczytaj [ochronę danych ESP32](server/PROTOCOL.pl.md#zabezpieczenie-danych-na-esp32). Pamięć działającego urządzenia klienta nie może być kasowana jako rutynowy krok migracji.

## Użytkowanie

1. Podłącz przygotowane urządzenie do prądu i zaloguj się w aplikacji Android.
2. Wybierz parowanie, zeskanuj QR egzemplarza i zaczekaj na wykrycie oraz uwierzytelnienie BLE.
3. Nazwij urządzenie, wybierz zgodną sieć Wi-Fi 2,4 GHz WPA2/WPA3 Personal i wpisz hasło. Zaczekaj na potwierdzenie, że urządzenie jest online na Twoim koncie.
4. Dodaj cel z adresem MAC komputera i urządzeniem w tej samej sieci.
5. Naciśnij budzenie. Sukces oznacza potwierdzenie wysłania magic packetu przez ESP32; komputer musi mieć dodatkowo włączone Wake-on-LAN w BIOS/UEFI i karcie sieciowej.

Niesparowany egzemplarz otwiera przy starcie dziesięciominutowe okno BLE. Aby odzyskać Wi-Fi sparowanego urządzenia, przytrzymaj dedykowany przycisk aktywny stanem niskim przez trzy sekundy przy włączaniu (domyślnie GPIO 4; sprawdź płytkę) i użyj tego samego QR. Zmiana Wi-Fi zachowuje tożsamość i właściciela konta. Przekazanie innemu kontu wymaga najpierw usunięcia urządzenia przez poprzedniego właściciela. Utrata sieci i błędne logowanie nie resetują własności. Pięć błędnych lokalnych prób uwierzytelnienia zamyka okno konfiguracji. Urządzenia ze starym identyfikatorem sprzed v3 mogą odzyskać Wi-Fi, jeśli należą do zalogowanego konta; ponowne przypisanie usuniętej starej tożsamości wymaga migracji serwisowej.

## Bezpieczeństwo i weryfikacja wydania

- Obaj klienci TLS sprawdzają łańcuch, nazwę hosta i daty; konfiguracja BLE używa SRP6a i AES-GCM.
- ESP32 zapisuje losowy 256-bitowy sekret przed przypisaniem. Identyfikator jest wyprowadzony z sekretu; claimy konta nie zastępują obecnego właściciela. Przerwane przypisanie można wznowić zapisanymi danymi.
- Baza przechowuje HMAC tokenów i sekretów z `TOKEN_PEPPER`; hasła kont używają Argon2. Aplikacja zapisuje token sesji w bezpiecznym magazynie Androida, a nie hasło konta.
- Hasło Wi-Fi przechodzi wyłącznie przez uwierzytelniony kanał lokalny. Aplikacja nie udostępnia tokenów claim ani ręcznych kontrolek sekretu.
- Przed wydaniem przetestuj sprzęt: błędny QR/hasło, błędy Wi-Fi, odmowę uprawnień, zanik zasilania podczas konfiguracji, utratę potwierdzenia claimu, odzyskanie offline, odnowienie certyfikatu i odrzucenie certyfikatu błędnego, wygasłego lub innego hosta. Testy serwera i kontrola TypeScript nie zastępują natywnego buildu Androida ani testów odbiorczych ESP32.
