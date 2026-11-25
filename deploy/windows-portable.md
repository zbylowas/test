# VIP-NET Internet Diagnostics v0.5.3 dla Windows x64

Uruchom `VIP-NET-Diagnostyka.exe` i wybierz **Wykonaj test**. Aplikacja rejestruje tożsamość klienta przy pierwszym połączeniu z serwerem, zapisuje kod w Menedżerze poświadczeń Windows i wykonuje pomiar w tle. Okno pokazuje wynik także przy częściowym pomiarze. Przycisk **Kopiuj kod do panelu** umożliwia logowanie na `https://diagnostics.example.org/klient`. Kod daje dostęp do Twoich raportów. Ten sam użytkownik Windows odzyskuje ostatni raport po ponownym uruchomieniu. Domyślny serwer to `https://diagnostics.example.org`. Administrator prywatnego stagingu może wskazać własny zaufany adres HTTPS przez `VIPNET_DESKTOP_ORIGIN`.

Pakiet stagingowy 0.5.3 nie ma podpisu Authenticode. Porównaj wynik `Get-FileHash .\VIP-NET-Diagnostyka.exe -Algorithm SHA256` z sumą podaną na stronie pobierania. Ostrzeżenie o nieznanym wydawcy dotyczy reputacji pliku. W przypadku wykrycia nazwanego zagrożenia pozostaw plik w kwarantannie i przekaż nazwę wykrycia oraz sumę pliku administratorowi.

Panel zapisuje IP przy rezerwacji i przy synchronizacji. Identyfikator instalacji Windows umożliwia wyszukanie historii po zmianie IP. Przy niedostępnym identyfikatorze instalacji aplikacja próbuje użyć klucza z profilu kolejki. Ponowna instalacja systemu może zmienić identyfikator. Klonowanie systemu może go powielić. Dostęp do historii zapewnia prywatny kod klienta.

## Silnik wiersza poleceń

Rozpakuj archiwum na Windows 10/11. W PowerShell uruchom `.\vipnet-mtr.exe --inventory`. Wynik zapisuje się w kolejce SQLite i trafia na stdout w UTF-8. Zawiera prywatne adresy lokalne i trasy. Opcja `--inventory` po parametrach MTR dołącza ten sam rodzaj inwentaryzacji do pomiaru, np. `.\vipnet-mtr.exe 5 4 400 127.0.0.1 --inventory`.

Do odczytu stanu służy `.\vipnet-mtr.exe --status`. Do wysyłki ustaw `VIPNET_API_ORIGIN` na zaufany origin HTTPS operatora i przekaż token klienta przez `VIPNET_TOKEN`. Następnie uruchom `.\vipnet-mtr.exe --sync`. Domyślny katalog kolejki to `%LOCALAPPDATA%\VIP-NET\Internet Diagnostics`. Profil można wskazać przez `VIPNET_QUEUE_DIR`. Klucz pseudonimów jest związany z katalogiem kolejki i kontem Windows przez DPAPI.

Odczyt Wi-Fi podlega uprawnieniom Windows. Dostępne wartości pochodzą z Native Wi-Fi API. Pozycje niedostępne mają stan i przyczynę. Plik OUI jest opcjonalny. Pobierz plik MA-L CSV z rejestru IEEE, przekształć go poleceniem `python import_oui.py oui.csv ma-l.tsv` i ustaw `VIPNET_OUI_FILE` na pełną ścieżkę TSV. Zestawienie producentów powstaje lokalnie. [Rejestr MA-L IEEE](https://standards-oui.ieee.org/oui/oui.csv)

## Transfer i bufferbloat

Polecenie `vipnet-mtr.exe --throughput` używa osobnego `VIPNET_NODE_ORIGIN` (bazowy adres HTTPS) i `VIPNET_NODE_TOKEN` wydanego dla kontrolowanego węzła. W stdout najpierw trafiają próbki MTR, a ostatnia linia zawiera dokument pomiaru. Sesja jest dostępna w SQLite do potwierdzenia wysyłki przez API. Pomiary trwają do limitu czasu profilu. Ctrl+C zachowuje dane częściowe. `VIPNET_API_ORIGIN` i `VIPNET_TOKEN` służą do przesyłania wyników. W profilu starszego węzła pobieranie i wysyłanie używają po jednym strumieniu. Aplikacja okienkowa na stagingu wykorzystuje do czterech strumieni HTTPS przez pięć sekund w każdym kierunku, ze wspólnym limitem 1 Gb/s. Klient wyłącza proxy systemowe na potrzeby transferu, weryfikuje certyfikat i porównuje adres innych połączeń z pierwszym połączeniem do węzła.

Po wybraniu **Wykonaj test** obserwuj bieżące Mb/s na wykresie pobierania i wysyłania. W raporcie znajdziesz kartę użytą przy rezerwacji HTTPS, parametry Wi-Fi, RAM i CPU oraz liczbę unikalnych sąsiadów widocznych na karcie i łącznie na komputerze. Pasywny odczyt ARP/IPv6 obejmuje również routery i telefony. Stan tablicy zależy od ruchu widzianego przez Windows. Starsze pomiary mogą nie zawierać informacji o użytej karcie.
