# Protokół WoL server (v2)

**Polski** | [English](PROTOCOL.en.md)

Dwa porty TLS (min. TLS 1.2), oba z tym samym certyfikatem serwera:

- `CLIENT_PORT` (domyślnie 8443): aplikacja mobilna/desktopowa,
- `DEVICE_PORT` (domyślnie 8444): urządzenia ESP32.

Klient i ESP muszą weryfikować certyfikat serwera (przypięty certyfikat albo własne CA wgrane do firmware/aplikacji). Bez tego TLS nie chroni przed MITM.

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

## Parowanie urządzenia (claim token)

```
App    -> Server : LOGIN / RESUME
App    -> Server : CREATE_CLAIM "Biurko"         -> ACK [claim_token, 600]
User   -> ESP    : claim_token przez konsolę szeregową ("claim <token>")
                   albo w firmware (Kconfig WOL_CLAIM_TOKEN, Wi-Fi: WOL_WIFI_SSID/PASSWORD)
ESP    -> Server : DEVICE_CLAIM claim_token      -> ACK [device_id, device_secret]
ESP              : zapisuje device_id i device_secret w NVS (szyfrowanym)
```

- Provisioningu przez BLE ani SoftAP nie ma. Wi-Fi i adres serwera są wkompilowane w firmware. Claim token można podać w Kconfig przy pierwszym flashowaniu albo później, bez ponownego flashowania, na konsoli UART poleceniem `claim <token>`. Token z konsoli ma pierwszeństwo.
- ESP pamięta ostatni token zużyty lub odrzucony przez serwer i nigdy nie wysyła go ponownie. Bez danych logowania i bez nowego tokenu nie łączy się z serwerem, tylko czeka na polecenie `claim`.
- Claim token ma 128 bitów, jest jednorazowy, ważny 10 minut i przypisany do konta. Nowy `CREATE_CLAIM` unieważnia poprzedni. `CHANGE_PASSWORD`, `RESET_PASSWORD` i `LOGOUT_ALL` unieważniają niewykorzystany claim.
- Po `DEVICE_CLAIM` połączenie jest od razu uwierzytelnione.
- Każde następne połączenie ESP zaczyna od `DEVICE_AUTH device_id device_secret`.
- Nowe połączenie z tym samym `device_id` zamyka poprzednie.

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
| `CREATE_CLAIM` | device_name | claim_token, ttl_seconds |
| `LIST_DEVICES` | (brak) | `[{id, name, online, last_seen_at}]` |
| `RENAME_DEVICE` | device_id, name | device_id, name |
| `REMOVE_DEVICE` | device_id | device_id; ESP dostaje `UNPAIRED` |
| `ROTATE_DEVICE_SECRET` | device_id | device_id (urządzenie musi być online; równoległe rotacje są wykonywane po kolei; bez potwierdzenia od ESP `device_unreachable`, a serwer rozłącza ESP) |
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
| `DEVICE_CLAIM` | claim_token | `ACK [device_id, device_secret]` |
| `DEVICE_AUTH` | device_id, device_secret | `ACK []`; zły lub źle sformatowany sekret daje `NACK invalid_credentials` |
| `PING` | (brak) | `PONG` (tylko po uwierzytelnieniu) |
| `PONG` | (brak) | brak odpowiedzi |
| `WAKE_ACK` | request_id | brak odpowiedzi |
| `SECRET_ACK` | request_id | brak odpowiedzi |

Serwer -> ESP:

| Komenda | Argumenty | Oczekiwana reakcja ESP |
|---|---|---|
| `PING` | (brak) | `PONG` |
| `WAKE_UP` | request_id, mac | wysłać magic packet, potem `WAKE_ACK request_id` |
| `SET_SECRET` | request_id, new_secret | zapisać w NVS, potem `SECRET_ACK request_id` |
| `UNPAIRED` | (brak) | skasować dane z NVS i czekać na nowy claim token z konsoli |

- Serwer wysyła `PING`, gdy przez 30 s nic nie przyszło, i rozłącza po 90 s ciszy.
- `WAKE_UP` u klienta kończy się `NACK device_unreachable`, jeśli `WAKE_ACK` nie przyjdzie w ciągu 5 s.
- Po `SET_SECRET` stary sekret działa, dopóki ESP nie potwierdzi nowego albo nie zaloguje się nowym.
- Jeśli `SECRET_ACK` nie przyjdzie w ciągu 5 s, serwer rozłącza ESP. Sekret, którym ESP zaloguje się ponownie (stary albo nowy), staje się jedynym ważnym.
- ESP nigdy nie odpowiada na `ACK`/`NACK`, żeby nie powstała pętla.
- ESP powinien używać cJSON (komponent `json` w ESP-IDF) zamiast ręcznego parsera. Ramki o zagnieżdżeniu większym niż 4 poziomy są odrzucane przed parsowaniem, bo rekurencyjny parser mógłby przepełnić stos zadania.
- Zapis do gniazda ma termin 10 s. Jeśli serwer przestanie odbierać dane, ESP zamyka połączenie i łączy się ponownie.

### Zabezpieczenie danych na ESP32

`device_secret` wystarcza, żeby podszyć się pod urządzenie, dlatego flash i NVS muszą być szyfrowane:

- [esp_client/sdkconfig.defaults](../esp_client/sdkconfig.defaults) włącza szyfrowanie flasha (tryb Development, można jeszcze flashować przez UART) i szyfrowanie NVS. Klucze NVS leżą w zaszyfrowanej partycji `nvs_keys` ([partitions.csv](../esp_client/partitions.csv)) i są generowane przy pierwszym uruchomieniu.
- Wersja produkcyjna: `idf.py -B build-release -D SDKCONFIG=sdkconfig.release -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.release" build`. Osobny plik `sdkconfig.release` jest konieczny, bo ESP-IDF czyta `SDKCONFIG_DEFAULTS` tylko przy tworzeniu nowego `sdkconfig`; istniejący `sdkconfig` z buildu deweloperskiego po cichu wygrałby z profilem release. Profil [sdkconfig.defaults.release](../esp_client/sdkconfig.defaults.release) przełącza szyfrowanie w tryb Release i włącza Secure Boot v2. Wcześniej trzeba wygenerować klucz podpisu: `espsecure.py generate_signing_key --version 2 secure_boot_signing_key.pem`. Trzymaj go poza repozytorium, bo bez niego nie wgrasz już nowego firmware.
- Już tryb Development przy pierwszym uruchomieniu zapisuje klucz szyfrowania w eFuse. Da się go potem wyłączyć tylko ograniczoną liczbę razy (na ESP32 trzy). Tryb Release i Secure Boot v2 są całkowicie nieodwracalne. Secure Boot v2 na zwykłym ESP32 wymaga układu w rewizji 3.0 lub nowszej.
- Zmiana tablicy partycji wymaga jednorazowego `idf.py erase-flash` na urządzeniach z poprzednim firmware, a po nim ponownego sparowania.

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
