# Historia wydań

## 0.7.6 · 2026-11-25

- Wszystkie 18 nazwanych profili gier i platform ma adres do wyboru. Opis odróżnia serwer rozgrywki, przekaźnik, punkt pomiarowy i usługę gry. Pole adresu można zaznaczyć i skopiować.
- Roblox i League of Legends mogą użyć publicznego adresu zapisanego przez grę na tym komputerze w ciągu ostatniej doby. Pomiar uruchamia użytkownik. Raport pokazuje również adres IP wybrany podczas rozwiązywania DNS.
- Portable zawiera katalog na pierwsze uruchomienie offline i korzysta z aktualizacji dostarczanych przez portal.

## 0.7.5 · 2026-11-25

- Instalator działa w prywatnym katalogu konta Windows, blokuje obie kopie programu pomocniczego na czas przygotowania i oczekuje na osobne potwierdzenie gotowości. Instalacja odbywa się z uprawnieniami zwykłego użytkownika. Podpisujący otrzymuje treść manifestu bezpośrednio z procesu pakowania.

## 0.7.4 · 2026-11-25

- Poprawiono współdzielenie uchwytu podczas zapisu strefy Internet. Test aktualizacji obejmuje działającą kopię portable. Pakowanie sprawdza wersję PE bez uruchamiania binarium i weryfikuje dozwolony certyfikat. Eksport CSV zapisuje etykiety katalogu jako tekst.

## 0.7.3 · 2026-11-25

- Windows sprawdza podpisany opis wydania po otwarciu aplikacji. W Ustawieniach można pobrać nowszy plik, zweryfikować go i zainstalować w tym samym miejscu. Nowa wersja działa od następnego uruchomienia.
- Klient sprawdza podpis RSA projektu, numer wersji, rozmiar i SHA-256. Plik pobrany z Internetu zachowuje oznaczenie strefy Windows.
- Dla CS2 i Dota 2 można wybrać przekaźnik Steam w Warszawie, Frankfurcie i Wiedniu. Raport wskazuje rodzaj celu. Dotychczasowe pomiary i opcja wpisania własnego hosta pozostają dostępne.


## 25 listopada 2026 · katalog gier

- Do katalogu dołączyły Dota 2 i PUBG: BATTLEGROUNDS. W profilu Valoranta można wybrać europejski cel pomiarowy Riot lub własny adres. Windows 0.7.2 pobiera listę z serwera przy pierwszym otwarciu widoku gier po uruchomieniu aplikacji.

## 0.7.2 · historia

- Zaznaczoną sesję można otworzyć klawiszem Enter, dwuklikiem lub przyciskiem „Otwórz raport”.

## 0.7.1 · Windows, MTR i gry

- Jedenaście szczegółowych widoków ze wspólną nawigacją, tabele, wykresy i historia.
- Własne cele MTR, ICMP i TCP 443, statystyki skoków i porównanie dwóch tras. Regionalne testy gier korzystają z katalogu serwera. Monitoring zapisuje przerwane sesje.
- Panele odczytują opcjonalne parametry sesji i umożliwiają eksport surowych próbek w formatach JSON, CSV i TXT. Wydruk strony umożliwia zapis do PDF.

## 0.6.0 · podgląd Windows

- Jasny ekran Podsumowanie, dwa profile testu, wykresy na żywo, siedem metryk, szczegóły diagnostyki i obsługa starszych raportów. Serwer 0.6.0 ogłasza obsługę nowych serii. Panele i eksport JSON zachowują chwilowe prędkości w postaci źródłowych liczników.

## 0.5.5 · 25 listopada 2026

- Aplikacja objaśnia pobieranie, wysyłanie, możliwe ograniczenia i brakujące odpowiedzi na trasie. Przycisk „Szczegóły techniczne” otwiera pełny raport. Klient wykonuje oddzielne pingi ICMP do routera wybranego dla trasy i do rzeczywistego serwera testu.
- Portal opisuje każdy pomiar, pokazuje czasy bezpośrednich pingów, liczniki transferu, statystyki routerów i podstawy wniosków. Można odczytać wcześniejsze sesje.
- Plik EXE ma własną ikonę prędkościomierza. W aktywnym oknie wskazówka ma 21 położeń zależnych od aktualnej szybkości.

## 0.5.4 · 25 listopada 2026

- Aplikacja Windows pokazuje na żywo półokrągły prędkościomierz ze wskazówką, wartość w Mb/s i wykres ostatnich sześciu sekund. Skala tarczy pochodzi z profilu węzła. Odczyty wynikają z rzeczywistej liczby przesłanych bajtów.

## 0.5.3 · 25 listopada 2026

- Okno Windows i oba panele pokazują połączenie używane przy rezerwacji HTTPS, sprzęt, karty i sygnał Wi-Fi. Raport podaje liczbę unikalnych sąsiadów widocznych dla Windows oraz osobno dla karty pomiarowej. Podczas pobierania i wysyłania wykres pokazuje bieżące Mb/s z liczników transferu.
- Starsze zapisy nadal można odczytać. Jeżeli zapis nie zawiera lokalnego adresu rezerwacji, raport wskazuje brak tej informacji.

## 0.5.2 · 25 listopada 2026

Pierwsza publiczna edycja całego projektu na licencji MIT. W aplikacji Windows wykres podczas testu pokazuje prędkość pobierania i wysyłania obliczoną z bieżących liczników WinHTTP. Raport zawiera potwierdzone liczniki węzła i próbki MTR. Portal pokazuje odpowiadające wersji EXE informacje o podpisie.

W odbiorze na Windows 11 przez publiczny IPv4 klient uzyskał 222,53 Mb/s pobierania i 197,19 Mb/s wysyłania oraz 60 próbek MTR. Limit węzła wynosił 1000 Mb/s. Publiczny IPv6 i zwrotny MTR przez WAN wymagają osobnego odbioru.

Pliki EXE budowane z publicznych źródeł mają zasoby PE z nazwą produktu i wersją. CI sprawdza odczyt obu wartości na Windows przed udostępnieniem artefaktu.
