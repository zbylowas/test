# VIP-NET Internet Diagnostics

Windows 1.1.1 pokazuje wyniki prędkości, opóźnienia, stan komputera, sieć i Wi-Fi w jasnych widokach. W MTR możesz wpisać adres lub nazwę DNS, ustawić rodzinę IP, wybrać ICMP lub TCP 443, obejrzeć poszczególne skoki i porównać trasy. Diagnostyka gier zawiera 18 profili gier i platform, w tym Roblox, Counter-Strike 2, Minecraft, Dota 2, League of Legends, Valorant i PUBG: BATTLEGROUNDS. Własny profil pozwala wpisać adres ręcznie. Historia zachowuje także przerwane pomiary. Budując własną dystrybucję, ustaw adres kontrolowanego serwera w pliku NetDiagnostics.ini lub w opcji CMake NETDIAG_DESKTOP_ORIGIN. [Konfiguracja Windows](deploy/windows-portable.md)

Adresy oraz wiersze można kopiować w oknie szczegółów. Opcja **Pokaż ruch procesów** w Podsumowaniu włącza odczyt Mb/s w zwykłym teście. Kontroler ETW Windows może wymagać zgody UAC. Aplikacja pokazuje ruch innych procesów do publicznych adresów przez kartę testu. Liczniki i nazwy procesów pozostają w pamięci aplikacji. W Sieci lokalnej hostname pochodzi z pamięci DNS komputera, a producent z lokalnej bazy OUI. Jawne adresy MAC pozostają na komputerze. Użytkownik może je skopiować lub wyeksportować.

## Kod i licencja

Twórcą projektu **VIP-NET Internet Diagnostics** jest **vip-net.pl**. [Strona twórcy](https://vip-net.pl)

Przy publikacji kopii projektu lub istotnej części kodu zachowaj plik `LICENSE` z informacją `Copyright (c) 2026 vip-net.pl` oraz tekstem licencji MIT. Ten zapis zachowuje oznaczenie **vip-net.pl** jako twórcy projektu.

Licencja MIT obejmuje autorski kod klienta Windows, portalu Vue, API Python z migracjami PostgreSQL, węzła pomiarowego, reguł analizy, kontraktów i testów. Zależności mają własne licencje. [Licencja projektu](LICENSE) · [Informacje o zależnościach](licenses/README.md)

## Kompilacja na Windows

Wymagane są MSVC z obsługą C++20, Windows SDK i CMake 3.21 lub nowszy. CMake pobiera zlib i nlohmann/json z adresów wskazanych w pliku budowy i sprawdza ich SHA-256.

~~~powershell
cmake -S client/windows -B build -A x64 -DVIPNET_ACCEPTANCE=ON
cmake --build build --config Release --parallel
.\build\Release\vipnet-summary-check.exe
.\build\Release\vipnet-mtr.exe --version
~~~

Uruchom plik VIP-NET-Diagnostyka.exe z katalogu build/Release i wybierz **Wykonaj test**. Ustawienie VIPNET_DESKTOP_ORIGIN pozwala skierować aplikację do własnej zgodnej instalacji HTTPS. [Instrukcja klienta](deploy/windows-portable.md)

## Panel, API i testy

Portal wymaga Node.js 24 i pnpm 11. Z katalogu frontend wykonaj poniższe polecenia.

~~~sh
pnpm install --frozen-lockfile
pnpm run build
~~~

API i worker korzystają z Pythona 3.12 i PostgreSQL 17. Instrukcja serwera opisuje tworzenie bazy, migracje, odrębne role i uruchamianie usług. [API i baza danych](server/README.md) · [Węzeł pomiarowy](measurement-node/README.md) · [Kontrakt API](contracts/v1/openapi.json)

~~~powershell
python -m pip install -r scripts/requirements-v010-test.txt
python -m unittest contracts.test_contracts rules.test_mtr rules.test_v020 rules.test_throughput measurement-node.test_transfer
python scripts/verify_windows.py build/Release/vipnet-mtr.exe -v
~~~

Testy sieciowe CI wykonują pomiary na loopback. Dane w docs/evidence tej edycji są przykładem zgodności dawnego formatu odtworzonym z próby loopback. Identyfikator i znaczniki czasu zastąpiono wartościami testowymi. Pakiet serwera zawiera kod oraz zbudowane zasoby WWW. Dołącz własną konfigurację środowiska dla wybranego hosta.

## Code signing policy

Dystrybutor może podpisywać pliki Windows oraz manifest aktualizacji własnym certyfikatem. Kompilacja ze źródeł obsługuje podpisane aktualizacje, gdy dystrybutor udostępni swój certyfikat publiczny w lokalnym pliku `client/windows/project-signer.b64` przed kompilacją. Jest to certyfikat DER zakodowany w Base64. Klucz prywatny pozostaje w magazynie wydawcy. [Wdrażanie podpisu SignPath i role zespołu](deploy/signpath.md) · [Dane pomiarowe](#dane-pomiarowe)

## Dane pomiarowe

Jeśli użytkownik lub dystrybutor ustawi adres serwera, aplikacja może przy starcie pobrać opis dostępnego wydania. Przed wysłaniem pomiarów użytkownik uruchamia test. Aplikacja przenośna działa bez instalatora. Jej pliki można usunąć po zamknięciu.

Po wybraniu **Wykonaj test** aplikacja okienkowa łączy się z wybranym serwerem HTTPS. W kompilacji ze źródeł adres odbiorcy podaje dystrybutor lub użytkownik. Program przesyła wyniki transferu i opóźnienia, odpowiedzi routerów, informacje o systemie, interfejsach, trasach i dostępnych parametrach Wi-Fi. Serwer zapisuje adres IP połączenia i pseudonim instalacji Windows. Wyniki są dostępne dla właściciela kodu klienta i uprawnionego operatora organizacji. Kolejka SQLite zachowuje oczekujące oraz częściowe wyniki. Kod klienta znajduje się w Menedżerze poświadczeń Windows. Zachowaj go dla siebie.

Do lokalnej próby MTR można użyć programu vipnet-mtr.exe z celem 127.0.0.1, pozostawiając VIPNET_API_ORIGIN i VIPNET_TOKEN nieustawione. Aplikacja przenośna nie wymaga instalatora. Pliki programu można usunąć po jego zamknięciu. Informacje o profilach i kolejce znajdują się w instrukcji klienta.
