# API, PostgreSQL i kolejka analityczna v0.4.0

Polecenia zakładają katalog główny repozytorium, Python 3.12 i dedykowany PostgreSQL. Wersję testowano z PostgreSQL 17.10. Najpierw zainstaluj zależności w osobnym venv.

```shell
python -m pip install -r server/requirements.txt
```

### Utworzenie i migracja

Administrator przygotowuje bazę internet_diagnostics z kodowaniem UTF8 i osobnym właścicielem oraz role LOGIN netdiag_api i netdiag_worker. Na nowej instancji można użyć createuser --pwprompt dla każdej roli i createdb --owner netdiag_owner internet_diagnostics. Ogranicz dostęp sieciowy bazy do procesów serwisowych. Rola właściciela wymaga uprawnień DDL i musi być osobna od obu ról uruchomieniowych.

Ustaw VIPNET_DATABASE_URL jako sekret w formacie `postgresql+psycopg://USER:PASSWORD@HOST:PORT/internet_diagnostics`. Dla zdalnego serwera dodaj parametry libpq weryfikujące certyfikat i nazwę (sslmode=verify-full, sslrootcert). Przy migracji użyj danych właściciela.

```shell
python -m alembic -c server/alembic.ini upgrade head
psql -d internet_diagnostics -v ON_ERROR_STOP=1 -f server/grants.sql
python -m server.maintenance
```

psql pobiera konto właściciela i host z własnych zmiennych PG lub serwisu libpq. Wykonuj te polecenia wyłącznie na bazie przeznaczonej dla diagnostyki. Aktualizacje nie uruchamiają migracji przy starcie API.

### Dostęp i uruchomienie

Operator instalacji nadaje organizacji stały UUID. W środowisku właściciela polecenie `python -m server issue-token UUID_ORGANIZACJI client` drukuje token raz. Wariant `operator` wydaje token do odczytu sesji całej organizacji. Przekaż token przez kanał wydawania poświadczeń. Identyfikator principal trafia na stderr. Polecenie `python -m server rotate-token PRINCIPAL_UUID` wymienia token zachowując własność sesji. `python -m server revoke-token PRINCIPAL_UUID` odwołuje dostęp. Wszystkie trzy operacje zapisują zdarzenie audytu.

API uruchom z poświadczeniami netdiag_api, worker z poświadczeniami netdiag_worker. Wybierz wcześniej sprawdzony wolny port. Dla bezpośredniego HTTPS podaj certyfikat serwerowy z łańcuchem i klucz z prywatnego katalogu. Windows wymaga zaufanego wystawcy i zgodnej nazwy.

```shell
python -m server serve --host 127.0.0.1 --port PORT --cert CHAIN.pem --key PRIVATE.key
python -m server.worker
```

Proxy kończące TLS musi nadpisywać X-Forwarded-For pojedynczym IP i X-Forwarded-Proto wartością https. Ustaw VIPNET_TRUSTED_PROXIES na dokładne adresy/CIDR tego proxy, ogranicz połączenia do backendu i użyj serwera z `python -m server serve`. Wbudowane przetwarzanie nagłówków przez Uvicorn jest wyłączone w tym punkcie wejścia. Domyślnie lista proxy jest pusta. Ogranicz częstotliwość ruchu przed uwierzytelnieniem i czas na przesłanie ciała na warstwie brzegowej. Podstawowe pomiary mają stan powiązania anonymous do wdrożenia adaptera LMS.

Kontrakt jest dostępny pod /api/v1/openapi.json, schematy obok niego. GET /api/v1/health kontroluje rewizję migracji i partycję bieżącego dnia. GET /api/v1/sessions przyjmuje limit i offset. GET /api/v1/sessions/{id} zwraca stan. Trzy operacje PUT zapisują kolejno otwarcie, porcję i manifest zamknięcia. Wszystkie operacje na sesjach wymagają Bearer i HTTPS od klienta.

### Utrzymanie

Codziennie uruchamiaj `python -m server.maintenance` z konta właściciela. Tworzy partycje na dziś i dwa kolejne dni UTC, usuwa przeterminowane partycje oraz klucze, wygasza analizy i zamyka porzucone otwarte sesje jako partial. Po takim zamknięciu dalsza nowa porcja wymaga ręcznego uzgodnienia. Worker używa SKIP LOCKED, dzierżawy i numeru generacji. `python -m server.worker --once` przetwarza najwyżej jedno zadanie. Automatyczny nadzór procesu ma wznawiać go po awarii. Monitoruj stan failed, wiek najstarszego gotowego zadania, błędy braku partycji oraz pojemność bazy.

| Zmienna | Domyślnie | Znaczenie |
| --- | ---: | --- |
| VIPNET_REQUESTS_PER_MINUTE | 300 | Żądania na token w minucie według UTC bazy |
| VIPNET_PEER_REQUESTS_PER_MINUTE | 900 | Żądania przed autoryzacją na adres źródłowy i proces API. Pamięć limitera obejmuje 4096 ostatnich adresów. |
| VIPNET_MAX_OPEN | 1000 | Otwarte sesje w całej bazie |
| VIPNET_SESSION_BYTES | 16777216 | Bajty zdekompresowanych porcji jednej sesji |
| VIPNET_OPEN_BYTES | 268435456 | Bajty porcji wszystkich równocześnie otwartych sesji |
| VIPNET_LEASE_SECONDS | 120 | Czas na pojedynczą analizę, przed ponownym przejęciem |
| VIPNET_RAW_DAYS / VIPNET_ANALYSIS_MONTHS | 90 / 24 | Retencja surowych próbek i analiz |
| VIPNET_IDLE_HOURS | 168 | Brak aktywności przed zamknięciem jako partial |

Jedno żądanie ma limit 256 KiB w transmisji i 1 MiB po dekompresji. API serializuje rezerwację pojemności przy zapisie sesji przez blokadę transakcyjną PostgreSQL. Test obciążeniowy musi określić wydajność tego rozwiązania na maszynie docelowej.

Backup wykonuj przy użyciu `pg_dump -Fc`, odtwarzaj do osobnej pustej bazy przez `pg_restore --single-transaction --exit-on-error`. Osobno zabezpiecz definicje ról klastra i ich poświadczenia. Sprawdź wersję Alembic, sumy treści, uprawnienia, gotowość API i kolejkę przed przełączeniem. Downgrade v010 usuwa dane aplikacji i jest przeznaczony do pustej bazy testowej. Rollback z danymi wymaga odtworzenia kopii do osobnej instancji.


## Odczyt i ponowna analiza MTR w v0.2.0

W bazie stagingowej jako właściciel wykonaj `python -m alembic -c server/alembic.ini upgrade head`, a następnie zastosuj ponownie `server/grants.sql`. Migracja v020 dodaje do sesji opcjonalne parametry pomiaru. Starsze sesje zachowują wartość null. Rola API potrzebuje prawa SELECT do diagnostics.analysis. Wysyłane z nowej wersji klienta próbki TCP mogą zawierać opcjonalne pole tcp_port. Zaktualizuj API przed klientem.

`GET /api/v1/sessions/{session_id}/analysis` zwraca wersję klienta i reguł, czas początku UTC, parametry pomiaru, SHA-256 manifestu wejściowego i zapisany wynik w zakresie tej samej sesji. Parametr `rules_version` domyślnie wybiera 0.2.0. Dla oczekującego zadania lub brakującej wersji API zwraca 404. Opcja `python -m server.worker --reanalyze UUID` na roli workera oblicza wynik dla wcześniej przeanalizowanej sesji, o ile nadal istnieją jej surowe próbki. Równoczesne wywołania zachowują pojedynczy rekord dla wersji i skrótu. Wcześniejszą interpretację można odczytać z `?rules_version=0.1.0`.

## Inwentaryzacja komputera i sieci w v0.3.0

Migracja `v030` dodaje opcjonalny dokument JSONB do otwarcia sesji i zachowuje dotychczasowe sesje. W pierwszej kolejności zaktualizuj bazę, granty i API. Odczyt `GET /api/v1/sessions/{session_id}/inventory` wymaga tokenu właściciela lub operatora jego organizacji. Brak dokumentu, uprawnień lub upłynięcie okresu retencji daje HTTP 404. Samodzielna inwentaryzacja ma pusty manifest próbek. Sesja z MTR nadal trafia do workera reguł 0.2.0. Dzienna retencja `VIPNET_RAW_DAYS` usuwa dokument i zachowuje metadane sesji. [Instrukcja wdrożenia na Linux](../deploy/linux/README.md)

## Przepustowość v0.4.0

Migracja `v040` dodaje opcjonalny dokument `core.session.throughput`. Poświadczenia klienta lub operatora organizacji umożliwiają `GET /api/v1/sessions/{session_id}/throughput`. Odpowiedź zawiera ten sam surowy dokument oraz interpretację 0.4.0. Brak dokumentu i sesja spoza zakresu dają 404. Obowiązuje retencja surowych danych i serwerowy czas przyjęcia. Usługa transferowa ma oddzielne poświadczenie i drogę przez proxy. [Instalacja węzła](../deploy/linux/README.md)
