# Historia wydań

## 0.5.3 · 25 listopada 2026

- Okno Windows i oba panele pokazują połączenie używane przy rezerwacji HTTPS, sprzęt, karty i sygnał Wi-Fi. Raport podaje liczbę unikalnych sąsiadów widocznych dla Windows oraz osobno dla karty pomiarowej. Podczas pobierania i wysyłania wykres pokazuje bieżące Mb/s z liczników transferu.
- Starsze zapisy nadal można odczytać. Jeżeli zapis nie zawiera lokalnego adresu rezerwacji, raport wskazuje brak tej informacji.

## 0.5.2 · 25 listopada 2026

Pierwsza publiczna edycja całego projektu na licencji MIT. W aplikacji Windows wykres podczas testu pokazuje prędkość pobierania i wysyłania obliczoną z bieżących liczników WinHTTP. Raport zawiera potwierdzone liczniki węzła i próbki MTR. Portal pokazuje odpowiadające wersji EXE informacje o podpisie.

W odbiorze na Windows 11 przez publiczny IPv4 klient uzyskał 222,53 Mb/s pobierania i 197,19 Mb/s wysyłania oraz 60 próbek MTR. Limit węzła wynosił 1000 Mb/s. Publiczny IPv6 i zwrotny MTR przez WAN wymagają osobnego odbioru.

Pliki EXE budowane z publicznych źródeł mają zasoby PE z nazwą produktu i wersją. CI sprawdza odczyt obu wartości na Windows przed udostępnieniem artefaktu.
