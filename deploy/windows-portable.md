# NetDiagnostics 0.7.1 · Windows x64

Uruchom EXE i wybierz **Rozpocznij test**. Profil **Pełna prędkość** korzysta z ustawień przepustowości kontrolowanego węzła. **Mały transfer** używa ustalonej porcji danych. **Pełny raport** otwiera objaśnienie, a **Dane techniczne** pokazują między innymi kartę, adresy IPv4 i IPv6 oraz MTR. Kod w widoku raportu lub historii umożliwia zalogowanie do panelu klienta. System przechowuje go w Menedżerze poświadczeń.

W widoku **MTR i Traceroute** wpisz adres IP albo nazwę hosta, wybierz metodę i kliknij **Wykonaj test**. Zaznacz wiersz skoku, aby odczytać jego statystyki i wykres opóźnień. **Porównaj trasę** zestawia dwa pomiary do tego samego celu wykonane z tymi samymi parametrami. **Pełny raport** otwiera szczegóły tej sesji.

W widoku **Gry online** wybierz profil i region albo podaj własny cel. Ping mierzy czas odpowiedzi celu, a MTR pokazuje drogę pakietów. **Monitoring** umożliwia obserwację do chwili zatrzymania. Przerwane pomiary otworzysz w **Historii**. Tabelę z wybranego widoku zapiszesz przyciskiem **Eksportuj**.

Adres serwera ustala dystrybutor przez opcję CMake `NETDIAG_DESKTOP_ORIGIN`. Można go zmienić w pliku `NetDiagnostics.ini` obok EXE. Zmienna środowiskowa `VIPNET_DESKTOP_ORIGIN` ma pierwszeństwo. Opcjonalny lokalny plik `operator.ico` zastępuje znak programu w nawigacji.

~~~ini
[NetDiagnostics]
Server=https://diagnostyka.example.org
Operator=NetDiagnostics
~~~

Panel zapisuje IP przy rezerwacji i przy synchronizacji. Identyfikator instalacji Windows umożliwia wyszukanie historii po zmianie IP. Przy niedostępnym identyfikatorze instalacji aplikacja próbuje użyć klucza z profilu kolejki. Ponowna instalacja systemu może zmienić identyfikator. Klonowanie systemu może go powielić. Dostęp do historii zapewnia prywatny kod klienta.

## Silnik wiersza poleceń

Rozpakuj archiwum na Windows 10/11. W PowerShell uruchom `.\vipnet-mtr.exe --inventory`. Wynik zapisuje się w kolejce SQLite i trafia na stdout w UTF-8. Zawiera prywatne adresy lokalne i trasy. Opcja `--inventory` po parametrach MTR dołącza ten sam rodzaj inwentaryzacji do pomiaru, np. `.\vipnet-mtr.exe 5 4 400 127.0.0.1 --inventory`.

Do odczytu stanu służy `.\vipnet-mtr.exe --status`. Do wysyłki ustaw `VIPNET_API_ORIGIN` na zaufany origin HTTPS operatora i przekaż token klienta przez `VIPNET_TOKEN`. Następnie uruchom `.\vipnet-mtr.exe --sync`. Domyślny katalog kolejki to `%LOCALAPPDATA%\VIP-NET\Internet Diagnostics`. Profil można wskazać przez `VIPNET_QUEUE_DIR`. Klucz pseudonimów jest związany z katalogiem kolejki i kontem Windows przez DPAPI.

Odczyt Wi-Fi podlega uprawnieniom Windows. Dostępne wartości pochodzą z Native Wi-Fi API. Pozycje niedostępne mają stan i przyczynę. Plik OUI jest opcjonalny. Pobierz plik MA-L CSV z rejestru IEEE, przekształć go poleceniem `python import_oui.py oui.csv ma-l.tsv` i ustaw `VIPNET_OUI_FILE` na pełną ścieżkę TSV. Zestawienie producentów powstaje lokalnie. [Rejestr MA-L IEEE](https://standards-oui.ieee.org/oui/oui.csv)

## Transfer i bufferbloat

Polecenie `vipnet-mtr.exe --throughput` używa osobnego `VIPNET_NODE_ORIGIN` (bazowy adres HTTPS) i `VIPNET_NODE_TOKEN` wydanego dla kontrolowanego węzła. W stdout najpierw trafiają próbki MTR, a ostatnia linia zawiera dokument pomiaru. Sesja jest dostępna w SQLite do potwierdzenia wysyłki przez API. Pomiary trwają do limitu czasu profilu. Ctrl+C zachowuje dane częściowe. `VIPNET_API_ORIGIN` i `VIPNET_TOKEN` służą do przesyłania wyników. W profilu starszego węzła pobieranie i wysyłanie używają po jednym strumieniu. Aplikacja okienkowa na stagingu wykorzystuje do czterech strumieni HTTPS przez pięć sekund w każdym kierunku, ze wspólnym limitem 1 Gb/s. Klient wyłącza proxy systemowe na potrzeby transferu, weryfikuje certyfikat i porównuje adres innych połączeń z pierwszym połączeniem do węzła.

Podczas pomiaru obserwuj dwie karty transferu. Wykres pokazuje przyrost bajtów w kolejnych przedziałach czasu. Duża liczba po teście jest średnią obliczoną z transferu potwierdzonego przez węzeł. Najedź na wykres, aby odczytać próbkę. Wybierz metrykę lub wiersz diagnostyki, aby poznać szczegóły. Osobno pokazujemy ping ICMP oraz mediany czasów odpowiedzi HTTPS pod obciążeniem. Starsze raporty mogą zawierać tylko średnie.

Program zachowuje ostatni raport i archiwum JSON w podkatalogu `reports` profilu klienta. Zapis może zawierać prywatne adresy. Serwer od wersji 0.6.0 ogłasza obsługę przebiegów w odpowiedzi rezerwacji. Po połączeniu z serwerem 0.5.5 pełne przebiegi pozostają w lokalnym raporcie, a poprzedni format pomiaru trafia do panelu.
