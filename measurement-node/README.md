# Węzeł pomiarowy Linux

## Pomiar zwrotny v0.2.0 na kontrolowanym Windows

`reverse.py` uruchamia jeden pomiar natywnym EXE. Operator przygotowuje adres źródłowy i UUID potwierdzonej sesji, odcisk SHA-256 certyfikatu klienta oraz prywatną lokalizację wyniku. Węzeł nasłuchuje przez 30 s na wskazanym adresie. Sprawdza adres połączenia, mTLS, odcisk klienta i UUID przekazany w jednej linii ASCII zakończonej LF. Adres do MTR pobiera z gniazda. Zlecenie wykonuje pięć rund ICMP, do TTL 16, z timeoutem 400 ms.

```text
python measurement-node/reverse.py --bind NODE_IP --port PORT --peer SOURCE_IP --session UUID --client-sha256 HEX --client-ca CA.pem --cert NODE.pem --key NODE.key --exe vipnet-mtr.exe --output PRIVATE_DIR
python -m rules.report FORWARD.ndjson --reverse-dir PRIVATE_DIR
```

Klient kontrolny i odtwarzalna próba są w `scripts/verify_reverse.py`. Katalog wyniku musi być nowy. Zawiera `reverse.ndjson`, parametry pary, skróty, log i lokalną kolejkę. Do porównania trasy w przód jej cel musi odpowiadać lokalnemu adresowi węzła. Przy NAT lub różnych punktach końcowych analiza wymaga odrębnej kwalifikacji.

## Węzeł Linux v0.4.0

Usługa `transfer.py` udostępnia ograniczone strumienie download/upload i próbki opóźnienia HTTPS. Wystawiany przez nią jednorazowy bilet jest związany z UUID i instancją węzła. Jeden proces przyjmuje jeden aktywny pomiar. Uruchomienie, profil i zakres Nginx opisuje instrukcja stagingu. [Wdrożenie Linux](../deploy/linux/README.md)

Dla pojedynczego autoryzowanego pomiaru powrotnego na Linux w poleceniu `reverse.py` podaj `--exe /opt/internet-diagnostics/current/measurement-node/linux_icmp.py`. Silnik wymaga systemowego `traceroute` obsługującego ICMP z prawem `CAP_NET_RAW` dla tego wykonania. Końcem trasy jest adres zweryfikowanego klienta mTLS. Pole `native_code` na Linux zawiera kod zakończenia narzędzia. W sieci z NAT należy potwierdzić zgodność końców trasy.

Pomiar UDP używa oddzielnego, krótkiego okna uzgodnionego z operatorem. Poniższe polecenia uruchamia się kolejno na węźle i kliencie, z uzgodnionymi adresem źródłowym, UUID i jednym portem TCP/UDP. Przez sesję mTLS węzeł wydaje jednorazowe wyzwanie. Klient wysyła dziesięć datagramów po 1200 bajtów co 100 ms. Odpowiedź z liczbą unikalnych datagramów i czasami przyjęcia wraca przez TLS. Węzeł odbiera dane tylko od źródła sesji. Zlecenia pomocnicze UDP i reverse uruchamia się pojedynczo na wyznaczonym porcie węzła.

```text
python measurement-node/udp.py receive NODE_IP PORT UUID --peer SOURCE_IP --client-sha256 HEX --cert NODE.pem --key NODE.key --ca CLIENT_CA.pem --output PRIVATE_NODE.json
python measurement-node/udp.py send NODE_IP PORT UUID --name NODE_TLS_NAME --cert CLIENT.pem --key CLIENT.key --ca NODE_CA.pem --output PRIVATE_CLIENT.json
```

Katalog hostów będzie obsługiwał LAN, Access, Core, Regional, Peering, Transit, Content, Cloud i International. AS39716, LUBMAN, EPIX, TPIX, MIX2, EPPOLMIX, Cogent, Cloudflare, Microsoft, Meta i Amazon to punkty odniesienia do kwalifikacji. Wpis uruchamialny wymaga zweryfikowanego adresu, zgody na dany rodzaj ruchu i limitów. Domyślna lista węzłów produkcyjnych jest pusta.

## Para pomiarów przez WAN

Na Windows klienta wykonaj `python scripts/wan_client.py prepare PATH_TO_EXE NODE_IP PRIVATE_FORWARD_DIR`. Otrzymany UUID i faktyczny adres źródłowy są potrzebne do uruchomienia węzła powyższym poleceniem. Na tym samym kliencie, w oknie nasłuchu węzła, wykonaj:

```text
python scripts/wan_client.py request PRIVATE_FORWARD_DIR --port PORT --server-name NODE_TLS_NAME --cert CLIENT.pem --key CLIENT.key --ca NODE_CA.pem
```

Narzędzie łączy się z numerycznym celem pomiaru w przód i sprawdza jego nazwę TLS oraz łańcuch. Odpowiedź `completed` potwierdza zapis po stronie węzła. Pobierz katalog zwrotny uzgodnionym prywatnym kanałem i wykonaj `python -m rules.report PRIVATE_FORWARD_DIR/forward.ndjson --reverse-dir PRIVATE_REVERSE_DIR`. Sprawdź rodzinę IP, zgodność końców oraz odstęp najwyżej pięciu minut. Zachowaj surowe próbki obu kierunków. Do dowodu trasy WAN potrzebne są dwa kontrolowane, niezależne końce.
