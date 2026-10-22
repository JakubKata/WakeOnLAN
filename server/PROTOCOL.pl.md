# Protokół WoL server (v3)

**Polski** | [English](PROTOCOL.md)

Dwa porty TLS (min. TLS 1.2), oba z tym samym certyfikatem serwera:

- `CLIENT_PORT` (domyślnie 8443): aplikacja mobilna/desktopowa,
- `DEVICE_PORT` (domyślnie 8444): urządzenia ESP32.

Aplikacja weryfikuje łańcuch certyfikatów i nazwę hosta przy użyciu systemowego magazynu zaufania Androida. ESP32 używa pakietu głównych CA z ESP-IDF z włączoną kontrolą łańcucha, nazwy hosta i ważności. Wymagana jest publiczna nazwa DNS i certyfikat CA zaufanego przez oba magazyny. Certyfikat serwera jest odnawiany przez ACME i nie jest wkompilowany w klientów. Zobacz [wdrożenie i odnawianie certyfikatu](../README.pl.md).

## Ramka

Jedna wiadomość = jeden obiekt JSON zakończony `\n`. Wiadomości do serwera mogą mieć maks. 4096 bajtów (nie licząc kończącego `\n`); odpowiedzi serwera nie mają tego limitu (np. `LIST_TARGETS` z 64 celami ma do ok. 55 KB, gdy nazwy składają się z emoji), więc klient powinien akceptować linie do 64 KiB:

```
{"COMMAND":[arg1,arg2,...]}\n
```

- Serwer wysyła wyłącznie ASCII (znaki spoza ASCII jako `\uXXXX`).
- Typy argumentów są sprawdzane ściśle (`"1"` to nie `1`, `true` to nie liczba).
- Odpowiedź: `{"ACK":[...]}` albo `{"NACK":["kod_bledu"]}`.
- Niepoprawny JSON daje `NACK bad_frame` i połączenie działa dalej. Za długa linia daje `NACK frame_too_long` i rozłączenie.
- Klient wysyła kolejne żądanie dopiero po odpowiedzi na poprzednie.

Limity czasu:
- 5 s na handshake TLS,
- 30 s na uwierzytelnienie, liczone od nawiązania połączenia. Kolejne wiadomości przed zalogowaniem nie przedłużają tego terminu, a trzecia niepoprawna ramka przed zalogowaniem kończy połączenie,
- 300 s bezczynności dla zalogowanego klienta (klient może wysyłać `PING`).

Limity połączeń są liczone osobno dla każdego portu, więc zalanie portu klienta nie blokuje urządzeń ESP i odwrotnie: 20 na adres IP i 1000 na port, w tym najwyżej 5 na adres IP i 256 na port połączeń jeszcze niezalogowanych (także w trakcie handshake TLS). Na serwerze wystawionym do internetu warto dodatkowo ograniczyć połączenia w zaporze, np. `iptables -A INPUT -p tcp --syn -m multiport --dports 8443,8444 -m connlimit --connlimit-above 20 -j REJECT`.

## Parowanie urządzenia przez BLE

1. Zalogowana aplikacja skanuje unikalną etykietę QR urządzenia i wykrywa jego usługę BLE.
2. Espressif Security 2 w wersji poprawki 1 uwierzytelnia sesję konfiguracji przez SRP6a i szyfruje ją AES-GCM. Hasło QR danego egzemplarza stanowi dowód posiadania; nazwa BLE służy wyłącznie wykrywaniu.
3. Przez zaszyfrowany endpoint `wol-claim` aplikacja odczytuje tożsamość urządzenia, skanuje pobliskie sieci Wi-Fi i zbiera wybraną nazwę SSID oraz hasło.
4. Aplikacja wysyła do serwera `CREATE_CLAIM device_name device_id` i otrzymuje `ACK [claim_token, 600]`.
5. Aplikacja przesyła token i bieżący czas Unix przez uwierzytelnioną sesję BLE, a następnie konfiguruje Wi-Fi standardowym endpointem Espressif. Hasło Wi-Fi nigdy nie trafia do serwera.
6. Urządzenie łączy się z serwerem przez zweryfikowany TLS, loguje się lub realizuje claim, a aplikacja potwierdza parowanie dopiero wtedy, gdy `LIST_DEVICES` zwraca ten identyfikator z `online: true` na zalogowanym koncie.

Urządzenie jednorazowo generuje 32 losowe bajty przed połączeniem z serwerem:

- `device_secret = base64url(random_bytes)` bez dopełnienia (43 znaki),
- `device_id = base64url(SHA256(random_bytes))` bez dopełnienia (43 znaki).

Tożsamość jest atomowo zapisywana w szyfrowanym NVS przed przypisaniem. Sekret pozostaje na urządzeniu i trafia wyłącznie do serwera TLS; aplikacja otrzymuje identyfikator, a nie sekret. Serwer sprawdza związek identyfikatora z sekretem podczas nowego claimu, więc znajomość samego identyfikatora nie pozwala zarezerwować go z innym sekretem. To przypisanie oparte na dowodzie posiadania, nie atestacja producenta.

| Nadawca | Żądanie | Wynik |
|---|---|---|
| Aplikacja → serwer | `CREATE_CLAIM device_name device_id` | `ACK [claim_token, 600]` |
| ESP → serwer | `DEVICE_AUTH device_id device_secret` | `ACK []`, jeśli urządzenie jest już przypisane |
| ESP → serwer | `DEVICE_CLAIM claim_token device_id device_secret` | `ACK [device_id]` |

- Claim token ma 128 bitów, jest ważny 10 minut i przypisany jednocześnie do konta oraz identyfikatora urządzenia. Nowy `CREATE_CLAIM` zastępuje poprzedni niewykorzystany claim konta; już przypisany identyfikator jest odrzucany jako `duplicate`. Zmiana hasła, reset hasła i `LOGOUT_ALL` unieważniają niewykorzystane claimy.
- Zużycie claimu, utworzenie urządzenia i kontrola właściciela są jedną transakcją. Claim innego konta nie może przepisać istniejącego urządzenia.
- Po utracie odpowiedzi na claim urządzenie nadal ma trwale zapisane dane logowania. Przy ponownym połączeniu próbuje `DEVICE_AUTH`. Powtórzenie pierwotnego udanego claimu z tym samym tokenem, identyfikatorem i sekretem jest idempotentne także po wygaśnięciu pierwotnego tokenu; nie wydaje nowych danych ani nie zmienia właściciela.
- Po udanym logowaniu lub claimie połączenie jest od razu uwierzytelnione. Nowe połączenie z tym samym identyfikatorem zastępuje poprzednie.
- Błędne dane logowania, awaria sieci lub błąd NVS nie uprawniają do kasowania tożsamości ani przejęcia przypisanego urządzenia. Odzyskanie konfiguracji Wi-Fi wymaga fizycznego uruchomienia trybu konfiguracji i danych QR; zachowuje tożsamość oraz przypisanie na serwerze.
- Ręczne wpisywanie tokenu i ręczna zmiana sekretu urządzenia nie są częścią protokołu. Aplikacja nie pokazuje tokenu claim ani sekretu urządzenia.

### Lokalny endpoint konfiguracji

`wol-claim` przenosi JSON UTF-8 wewnątrz uwierzytelnionej sesji Espressif Security 2. Nie jest to nieuwierzytelniony endpoint HTTP.

| Żądanie | Odpowiedź / przeznaczenie |
|---|---|
| `{"op":"info"}` | `{"device_id":"…","paired":false}`; `paired` opisuje lokalny stan przypisania |
| `{"op":"claim","token":"…","time":1780000000}` | `{"ok":true}` po walidacji i zapisaniu claimu dla nieprzypisanego urządzenia |
| `{"op":"configure","time":1780000000}` | Odzyskanie Wi-Fi/czasu już sparowanego urządzenia; nie zmienia właściciela |

UUID usługi BLE: `021a9004-0382-4aea-bff4-6b3f1c5adfb4`. Niesparowane urządzenie otwiera konfigurację na dziesięć minut przy starcie; sparowane wymaga przytrzymania aktywnego stanem niskim GPIO przez trzy sekundy przy włączaniu (domyślnie GPIO 4, sprawdź płytkę). Pięć błędnych prób uwierzytelnienia zamyka okno. Pola QR: `{"ver":"v1","name":"WOL_…","transport":"ble","security":2,"username":"…","pop":"…"}`. Każdy egzemplarz ma własną nazwę użytkownika/hasło oraz odpowiadającą im sól i weryfikator SRP zapisane w produkcji. Nie wolno dostarczać wspólnego hasła testowego. Dane QR nie mogą trafiać do logów, analityki ani publicznego repozytorium.

## Komendy klienta (`CLIENT_PORT`)

Przed zalogowaniem:

| Komenda | Argumenty | ACK |
|---|---|---|
| `REGISTER` | name, email, password | session_token, name |
| `LOGIN` | name, password | session_token, name |
| `RESUME` | session_token | name |
| `REQUEST_PASSWORD_RESET` | email | (puste); kod idzie na e-mail |
| `RESET_PASSWORD` | email, code, new_password | session_token, name; wszystkie inne sesje unieważnione |

Po zalogowaniu:

| Komenda | Argumenty | ACK |
|---|---|---|
| `PING` | (brak) | odpowiedź `PONG`; przed zalogowaniem `NACK unauthenticated` |
| `LOGOUT` | (brak) | (puste), potem rozłączenie |
| `LOGOUT_ALL` | (brak) | (puste), unieważnia wszystkie tokeny, kody resetu i claimy, potem rozłącza |
| `CHANGE_PASSWORD` | old, new | nowy session_token; inne sesje, kody resetu i claimy zostają unieważnione |
| `CHANGE_NAME` | new_name, password | new_name |
| `DELETE_ACCOUNT` | password | (puste); urządzenia dostają `UNPAIRED`, potem rozłączenie |
| `CREATE_CLAIM` | device_name, device_id | claim_token, ttl_seconds |
| `LIST_DEVICES` | (brak) | `[{id, name, online, last_seen_at}]` |
| `RENAME_DEVICE` | device_id, name | device_id, name |
| `REMOVE_DEVICE` | device_id | device_id; ESP dostaje `UNPAIRED` |
| `ADD_TARGET` | device_id, mac, name | `{id, device_id, mac, name}` |
| `LIST_TARGETS` | (brak) | `[{id, device_id, mac, name}]` |
| `RENAME_TARGET` | target_id (int), name | target_id, name |
| `ASSIGN_TARGET` | target_id (int), device_id | target_id, device_id |
| `REMOVE_TARGET` | target_id (int) | target_id |
| `WAKE_UP` | target_id (int) | target_id, dopiero po potwierdzeniu przez ESP; na konto 10 naraz, potem 1 co 6 s (`rate_limited`) |

Session token jest ważny 30 dni od ostatniego użycia. Aplikacja przechowuje go w bezpiecznym magazynie (Keychain/Keystore) zamiast hasła.

Unieważnienie sesji (`CHANGE_PASSWORD`, `RESET_PASSWORD`, `LOGOUT_ALL`) jest ostateczne: `LOGIN` albo `RESUME`, które trwały w tym samym czasie, kończą się odpowiednio `NACK invalid_credentials` i `NACK invalid_token`. Serwer co najmniej raz na minutę sprawdza, czy sesja zalogowanego połączenia nadal istnieje. Jeśli nie, dowolna komenda dostaje `NACK invalid_token` i połączenie jest zamykane.

Logowanie: nieudane próby są liczone per (konto, adres IP): 10 prób naraz, potem 1 na minutę, oraz luźniej per konto: 100 prób naraz, potem 1 co 36 s (ok. 100 na godzinę). Ktoś obcy nie zablokuje więc logowania właścicielowi z innego adresu. Próba jest pobierana z limitu przed sprawdzeniem hasła i zwracana po udanym logowaniu, więc równoległe próby z kilku połączeń też się liczą.

`REGISTER` odpowiada `account_exists`, gdy nazwa lub e-mail są zajęte. To świadomy kompromis: nazwa użytkownika i tak musi być unikalna i widoczna przy rejestracji. Sprawdzanie adresów jest ograniczone limitem na adres IP i osobnym limitem na adres e-mail (3 próby naraz, potem 1 co 10 minut).

Reguły pól:
- name: `[A-Za-z0-9_.-]{3,32}`, wielkość liter bez znaczenia,
- password: 8–128 znaków,
- nazwy urządzeń i celów: 1–64 znaki bez znaków sterujących,
- MAC: `AA:BB:CC:DD:EE:FF`, `AA-BB-...`, `AABB.CCDD.EEFF` lub `AABBCCDDEEFF`, bez adresów multicast/broadcast.

Po usunięciu urządzenia jego cele zostają z `device_id = null`. `ASSIGN_TARGET` przypina je do innego urządzenia.

### Odzyskiwanie hasła

```
App    -> Server : REQUEST_PASSWORD_RESET "jan@example.com"  -> ACK []
Server -> e-mail : kod w postaci "7K3QD-9XW2M"
App    -> Server : RESET_PASSWORD "jan@example.com" "7K3QD-9XW2M" "nowe hasło"
                                                              -> ACK [session_token, name]
```

- `REQUEST_PASSWORD_RESET` zawsze odpowiada `ACK []` (także dla nieznanego adresu), więc nie da się nim sprawdzić, czy e-mail jest zarejestrowany. Aplikacja pokazuje komunikat w stylu „jeśli konto istnieje, wysłaliśmy kod”.
- Kod ma 10 znaków (cyfry i litery bez I, L, O, U), jest ważny 15 minut i jednorazowy. Wielkość liter, spacje i myślniki nie mają znaczenia; `O`, `I`, `L` są czytane jako `0`, `1`, `1`.
- Nowe żądanie unieważnia poprzedni kod. Próby są ograniczone dla pary (e-mail, adres IP) do 5 naraz, potem 1 na minutę, a po 50 błędnych próbach łącznie kod przepada. Wysoki limit łączny sprawia, że ktoś obcy nie „spali” kodu właściciela, a przy około 50 bitach entropii zgadnięcie kodu jest nadal niewykonalne. `CHANGE_PASSWORD` też unieważnia kod.
- Zły, wygasły lub zużyty kod daje `NACK invalid_token`.
- Po udanym resecie wszystkie sesje i claimy konta są unieważnione, a połączenie jest od razu zalogowane nowym tokenem.
- Bez skonfigurowanego SMTP obie komendy dają `NACK reset_unavailable`.

## Komendy ESP (`DEVICE_PORT`)

ESP -> serwer:

| Komenda | Argumenty | Odpowiedź serwera |
|---|---|---|
| `DEVICE_CLAIM` | claim_token, device_id, device_secret | `ACK [device_id]`; tożsamość musi pasować do sekretu i claimu |
| `DEVICE_AUTH` | device_id, device_secret | `ACK []`; zły lub źle sformatowany sekret daje `NACK invalid_credentials` |
| `PING` | (brak) | `PONG` (tylko po uwierzytelnieniu) |
| `PONG` | (brak) | brak odpowiedzi |
| `WAKE_ACK` | request_id | brak odpowiedzi |

Serwer -> ESP:

| Komenda | Argumenty | Oczekiwana reakcja ESP |
|---|---|---|
| `PING` | (brak) | `PONG` |
| `WAKE_UP` | request_id, mac | wysłać magic packet, potem `WAKE_ACK request_id` |
| `UNPAIRED` | (brak) | usunąć stan przypisania i oczekujący claim, zachować tożsamość; kolejny start otwiera ograniczone okno konfiguracji BLE |

- Serwer wysyła `PING`, gdy przez 30 s nic nie przyszło, i rozłącza po 90 s ciszy.
- `WAKE_UP` u klienta kończy się `NACK device_unreachable`, jeśli `WAKE_ACK` nie przyjdzie w ciągu 5 s.
- ESP nigdy nie odpowiada na `ACK`/`NACK`, żeby nie powstała pętla.
- ESP powinien używać cJSON (komponent `json` w ESP-IDF) zamiast ręcznego parsera. Ramki o zagnieżdżeniu większym niż 4 poziomy są odrzucane przed parsowaniem, bo rekurencyjny parser mógłby przepełnić stos zadania.
- Zapis do gniazda ma termin 10 s. Jeśli serwer przestanie odbierać dane, ESP zamyka połączenie i łączy się ponownie.

### Zabezpieczenie danych na ESP32

`device_secret` wystarcza, żeby podszyć się pod urządzenie, dlatego flash i NVS muszą być szyfrowane:

- [esp_client/sdkconfig.defaults](../esp_client/sdkconfig.defaults) włącza szyfrowanie flasha (tryb Development, można jeszcze flashować przez UART) i szyfrowanie NVS. Klucze NVS leżą w zaszyfrowanej partycji `nvs_keys` ([partitions.csv](../esp_client/partitions.csv)) i są generowane przy pierwszym uruchomieniu.
- Wersja produkcyjna: `idf.py -B build-release -D SDKCONFIG=sdkconfig.release -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.release" build`. Osobny plik `sdkconfig.release` jest konieczny, bo ESP-IDF czyta `SDKCONFIG_DEFAULTS` tylko przy tworzeniu nowego `sdkconfig`; istniejący `sdkconfig` z buildu deweloperskiego po cichu wygrałby z profilem release. Profil [sdkconfig.defaults.release](../esp_client/sdkconfig.defaults.release) przełącza szyfrowanie w tryb Release i włącza Secure Boot v2. Wcześniej trzeba wygenerować klucz podpisu: `espsecure.py generate_signing_key --version 2 secure_boot_signing_key.pem`. Trzymaj go poza repozytorium, bo bez niego nie wgrasz już nowego firmware.
- Już tryb Development przy pierwszym uruchomieniu zapisuje klucz szyfrowania w eFuse. Da się go potem wyłączyć tylko ograniczoną liczbę razy (na ESP32 trzy). Tryb Release i Secure Boot v2 są całkowicie nieodwracalne. Secure Boot v2 na zwykłym ESP32 wymaga układu w rewizji 3.0 lub nowszej.
- Dane fabryczne i zmiany partycji wymagają kontrolowanej procedury produkcyjnej lub serwisowej. Nie kasuj działającego urządzenia podczas rutynowej aktualizacji: usunęłoby to jego trwałą tożsamość i ustawienia Wi-Fi.

### Aktualizacje firmware i magazynu zaufania

Układ partycji zawiera dwa sloty OTA i metadane rollbacku oraz wymaga co najmniej 4 MB flash. W profilu release podpisane aktualizacje HTTPS wymagają Secure Boot, anti-rollback i `WOL_ENABLE_OTA`; ustaw stały `WOL_FIRMWARE_URL` dla dokładnego produktu/układu. Publikuj podpisany obraz o tej samej nazwie projektu i ściśle nowszym numerycznym `PROJECT_VER` (`major.minor.patch`). Jego secure version nie może maleć ani być niższe od minimum eFuse. Stały URL musi zwracać bezpośrednio HTTP 200 ze znanym `Content-Length` mieszczącym się w slocie OTA; przekierowania, transmisje chunked i niepodpisane obrazy są odrzucane. Pobieranie ma łączny limit dziesięciu minut.

Stabilny obraz planuje aktualizacje niezależnie od logowania do serwera przekazującego, po początkowym opóźnieniu 30–330 sekund, następnie co 24 godziny z dodatkowym losowym opóźnieniem do godziny. Sprawdzenie czeka na zamknięcie konfiguracji BLE. Pozwala to odzyskać działanie przy problemie z zaufaniem serwera, jeśli skonfigurowany host aktualizacji nadal jest zaufany. Obraz oczekujący na potwierdzenie startu nie uruchamia kolejnych aktualizacji, dopóki nie potwierdzi go logowanie do chmury. Najpierw zapisywany jest nieaktywny slot. Nowy obraz zostaje zatwierdzony dopiero po logowaniu do chmury; jeśli nie nastąpi to w ciągu 120 sekund, bootloader wraca do poprzedniego obrazu. Zwykłe OTA zachowuje NVS. Pakiet głównych CA jest aktualizowany w podpisanym obrazie firmware. Dostarczaj nowe korzenie z okresem wspólnego zaufania przed zmianą łańcucha serwera lub hosta firmware. Zachowaj działający zaufany łańcuch pobierania dla wspieranych urządzeń offline; OTA nie uruchomi się przez łańcuch, któremu stare firmware już nie ufa.

Pierwsza migracja ze starego układu z pojedynczą aplikacją wymaga kontrolowanej procedury serwisowej; nie da się jej dostarczyć zwykłym OTA samej aplikacji. Zmiany Secure Boot i wersji eFuse są nieodwracalne. Przed wdrożeniem sprawdź aktualizację, rollback, przerwane pobieranie i zanik zasilania na płytce produkcyjnej.

### Uruchamianie zegara

Konfiguracja przekazuje czas telefonu przez uwierzytelnioną sesję BLE. Przy kolejnych startach czas dostarcza zwykły SNTP, z dolną granicą 2026-01-01 i ostatnim trwałym znacznikiem z udanego logowania do chmury. Punkt czasu jest zapisywany najwyżej raz dziennie. SNTP zatrzymuje się bezpośrednio po początkowej próbce; nie zmienia okresowo zegara trwającej sesji. TLS nadal sprawdza daty certyfikatów i nigdy nie przechodzi na niezaufane połączenie. **SNTP nie uwierzytelnia czasu**: dolna granica zapobiega cofnięciu poniżej punktu, lecz wroga sieć może nadal manipulować dostępnością i czasem w dopuszczonym zakresie. Silniejszy model ochrony czasu wymaga chronionego RTC albo uwierzytelnionej usługi czasu. Fizyczne odzyskiwanie przez BLE, wymagające przytrzymanego przycisku i unikalnego dowodu QR/SRP, może naprawić błędny punkt z przyszłości, zastępując go bieżącym czasem telefonu. Ten wyjątkowy tryb może obniżyć zapisaną granicę, lecz nigdy poniżej 2026-01-01. Automatyczna konfiguracja bez fizycznej czynności nie może jej obniżyć.

## Aktualizacja z protokołu v2

Zmieniły się listy argumentów claimów; dla nowego parowania wdrażaj serwer, aplikację i firmware łącznie. Istniejące dane `DEVICE_AUTH` pozostają obsługiwane. Aplikacja pozwala odzyskać Wi-Fi dla starego identyfikatora już należącego do zalogowanego konta; stare urządzenie usunięte z konta wymaga kontrolowanej migracji serwisowej przed nowym przypisaniem v3, zamiast cichego wygenerowania innej tożsamości. Migracja bazy wyłącznie do przodu usuwa stare oczekujące claimy bez powiązania z urządzeniem, dodaje to powiązanie i zachowuje skrót udanego claimu dla bezpiecznych powtórzeń. Oczekujący stary sekret pozostaje tylko do jednorazowego odzyskania urządzenia przerwanego w trakcie dawnej rotacji; pierwsze poprawne logowanie rozstrzyga zapisane dane. Nie istnieje API uruchamiające kolejną rotację.

Aktualizacja firmware na istniejącym sprzęcie wymaga przetestowanego planu migracji danych fabrycznych, NVS i układu partycji. Nie kasuj urządzenia klienta jako rutynowego kroku aktualizacji. Wykonuj kopie bazy oraz `TOKEN_PEPPER`; zmiana lub utrata peppera unieważnia istniejące dane logowania.

## Kody błędów (`NACK`)

| Kod | Znaczenie |
|---|---|
| `bad_frame` | niepoprawny JSON / format ramki |
| `frame_too_long` | linia od klienta > 4096 B (połączenie zamykane) |
| `unknown_command` | brak takiej komendy dla tej roli portu |
| `bad_args` | zła liczba lub typ argumentów |
| `unauthenticated` / `already_authenticated` | zły stan sesji |
| `rate_limited` | za dużo prób, spróbuj później |
| `invalid_credentials` | złe hasło / sekret urządzenia |
| `invalid_token` | nieważny session token albo claim token |
| `invalid_name`, `invalid_email`, `invalid_label`, `invalid_mac`, `weak_password` | walidacja pól |
| `account_exists` | nazwa lub e-mail zajęte przy rejestracji |
| `name_taken` | nazwa zajęta przy `CHANGE_NAME` |
| `not_found` | brak obiektu albo należy do innego konta |
| `duplicate` | ten MAC już jest na liście |
| `limit_reached` | limit urządzeń (10) lub celów (64) |
| `no_device` | cel nie jest przypisany do urządzenia |
| `device_offline` | urządzenie niepołączone |
| `device_unreachable` | urządzenie nie potwierdziło w czasie |
| `reset_unavailable` | serwer nie ma skonfigurowanego SMTP, reset hasła wyłączony |
| `internal` | błąd serwera (szczegóły w logu) |
