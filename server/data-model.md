# Model logiczny PostgreSQL dla v0.1.0 i dalszych etapów

**Stan v0.1.0.** Migracja v010 wprowadza dziewięć przestrzeni nazw, tabele sesji i porcji, partycjonowane próbki JSONB, klucze deduplikacji, tożsamości, audyt, zadania i analizy. W tej wersji analiza agreguje serie w obrębie sesji. Relacje run, profile hostów, inwentaryzacja urządzeń, integracje i raporty należą do dalszych etapów. Schemat fizyczny i aktualne operacje utrzymaniowe opisano w [migracji](migrations/versions/v010.py) i [instrukcji serwera](README.md).

Dedykowana baza internet_diagnostics. Czasy mają typ timestamptz i są prezentowane w UTC, IP to inet, delegacje to cidr. W etapie 0 model jest projektem przed migracjami. Pole measured_at pochodzi z klienta, received_at ustala serwer. Do retencji i stwierdzania świeżości przyjęcia używamy zegara serwera.

| Schemat i relacja | Klucz i relacje | Zawartość oraz dostęp |
| --- | --- | --- |
| core.session | UUID PK, właściciel i zakres operatora | Wersja, tryb, start/koniec, stan, źródło po HTTPS, stan dopasowania. Indeks (owner_id, received_at, id) dla historii. |
| core.chunk | PK (session_id, sequence), FK sesja | SHA-256 zdekompresowanych bajtów, liczba rekordów, czas przyjęcia. Ponowienie porównuje skrót pod blokadą. |
| device.snapshot | PK (session_id, snapshot_no) | System, CPU, RAM, sterowniki, interfejsy i jawna przyczyna braku odczytu. |
| lan.observation | FK sesja i interfejs | Adresacja, MTU, brama, DNS, liczniki, Wi-Fi, pseudonim MAC z rotowanym kluczem w zakresie sesji. Unikalność dotyczy jednej sesji. |
| measurement.profile / target / run | Wersjonowane profile, UUID run, FK sesja i profil | Rodzina IP, zweryfikowany adres, port/usługa, grupa, faza, budżety. Snapshot profilu w chwili startu. |
| mtr.sample | partycja dzienna po dacie przyjęcia UTC | Klucz (received_day, session_id, sequence, row_no). W każdym wierszu pełna próbka v1. Indeks (session_id, target, protocol, phase, ttl, attempt). |
| mtr.sample_key | PK (session_id, target, protocol, phase, ttl, attempt) | Globalna ochrona przed powtórzeniem próbki w innej porcji lub partycji. Wstawienie klucza i próbki w transakcji. Sprzątanie wraz z retencją. |
| mtr.hop_stats / diagnostics.analysis | FK run, wersja reguł, odcisk danych | Statystyki per TTL, lista adresów, diagnozy z dowodami, pewnością, ograniczeniami i dalszym testem. Unikalny (run, rules_version, input_digest). |
| diagnostics.job | UUID PK, unikalny klucz logicznego zadania | Stan, attempts, available_at, lease_until, generation i ostatni błąd. Indeks na gotowych zadaniach. |
| integration.observation | UUID, FK sesja, typ adaptera | Minimalny odczyt, źródło, observed_at, fetched_at, expires_at, matched/ambiguous/anonymous/unavailable. |
| report.share | UUID, FK wersja raportu | Skrót tokenu 256-bitowego, expires_at, revoked_at, wariant odbiorcy. Publiczny dostęp wyłącznie do projekcji klienta. |
| security.principal / grant / audit | Osobne role i przydziały, audyt append-only | Zakres sesji/organizacji, zmiany uprawnień i dostęp do raportów. Bez tokenów i pełnych nagłówków. |

### Transport sesji

1. Klient losuje UUID przy starcie. PUT sesji jest dozwolony właścicielowi uprawnionemu do otwarcia. Identyczne ponowienie zwraca poprzedni stan. Przechwycenie UUID nie nadaje dostępu. Bootstrap sesyjnego tokenu portable wymaga ustalonej polityki rejestracji przed udostępnieniem API.
2. Porcje od 0 do 65535, maksymalnie 256 próbek w porcji. Numer jest częścią ścieżki. API waliduje zgodność sesji i unikalność logicznych próbek. Limit projektu to 256 KiB na łączu i 1 MiB po dekompresji, obsługiwane kodowania identity/gzip. Odrzucenie przekroczenia limitem 413. Kolejność dostarczenia porcji jest dowolna.
3. Otwarcie, przyjęcie porcji i zamknięcie serializują zmiany dla tej samej sesji. Powtórzenie identycznej porcji działa również po zamknięciu. Inne bajty pod tym samym numerem, nowa porcja po zamknięciu oraz niezgodny manifest dają 409. Dla chunk_count = N wymagany jest dokładny zbiór numerów 0..N−1, dla zera zbiór pusty. Globalne limity bajtów i liczby aktywnych sesji należy egzekwować transakcyjnie.
4. Stan końcowy to completed, partial, cancelled lub failed. Awaria bez końcowego żądania pozostawia stan open do odzyskania z kolejki. Po konfigurowalnym oknie nieaktywności worker finalizuje sesję jako partial z przyczyną i audytem. Politykę późnych danych sprawdzić testem przed produkcją.
5. Domyślnie surowe próbki 90 dni, analizy i statystyki 24 miesiące. Retencja jest konfigurowalna. Po upływie okresu próbek ponowna analiza zwraca brak danych źródłowych. Metadane sesji oraz wykaz uruchomień mają odrębną politykę uzgodnioną z administratorem. Kopie zapasowe podlegają własnej retencji. Partycje przygotowuje worker przed granicą dnia, alarmuje przy braku kolejnej i usuwa wyłącznie zakresy całkowicie przeterminowane.

Migracja v020 zachowuje w `core.session.measurement` parametry przyjęte w dokumencie otwarcia. Obejmują numer kompilacji Windows, cele, protokół, rundy, TTL, timeout, odstęp i tryb fazowy. Dla starych rekordów wartość jest NULL. Wynik analizy odwołuje się do tej samej sesji i osobnej wersji reguł.

## Inwentaryzacja v0.3.0

`core.session.inventory` jest opcjonalnym dokumentem JSONB z otwarcia sesji. Zawiera czas UTC i zmierzone pola z ich stanami, a także prywatną adresację stanowiska i pseudonimy identyfikatorów warstwy łącza. API wiąże dokument z właścicielem sesji. Retencja wyznacza termin według serwerowego czasu przyjęcia sesji i czyści kolumnę. Starsze rekordy mają NULL. [Migracja v030](migrations/versions/v030.py)

## Transfer v0.4.0

`core.session.throughput` przechowuje JSONB z identyfikatorem sesji, profilem, adresatem, oknami pomiarowymi, licznikami obu stron i stanami kierunków. Serwer sprawdza identyfikator i zgodność potwierdzeń. Starsze sesje zawierają NULL. Dokument podlega retencji danych surowych. [Migracja v040](migrations/versions/v040.py)

## Próbki transferu 0.6.0

API przyjmuje opcjonalne liczniki czasu i bajtów pod kluczem `desktop_trace` w dotychczasowym JSONB `core.session.throughput`. Ten sam zakres uprawnień i retencja obejmują próbki. Klient wysyła je po ogłoszeniu `accepts_desktop_trace` przez serwer. Przy zapisie API sprawdza identyfikator sesji, początek obu serii, porządek czasów, monotoniczność bajtów i zgodność z licznikiem aplikacji. Starsze wiersze są czytane bez migracji.
