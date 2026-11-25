# Samodzielne uruchomienie diagnostyki

Uruchom API, worker oraz zadanie utrzymania w osobnej bazie PostgreSQL według instrukcji serwera. Role API i workera mają osobne poświadczenia. Ustaw własny origin HTTPS i ogranicz ruch do zasobów dostępnych dla tej instalacji. [Baza, migracje i usługi](../../server/README.md)

Wersja z rejestracją klientów wymaga jednego UUID organizacji w security.portal_issuer. Rekord dodaje właściciel bazy. W środowisku procesu API ustaw VIPNET_ENROLL_KEY na własną losową wartość o długości co najmniej 32 znaków. Użyj tego samego UUID organizacji przy wydawaniu kodu operatora. Pozostawienie klucza nieustawionego wyłącza nowe rejestracje.

Zbuduj panel według README. Wywołanie scripts/package_release.py po kompilacji tworzy paczkę serwera z panelem, aplikacją Windows, metadanymi Authenticode i licencjami. Rozpakuj ją do katalogu wybranego dla serwera. Domyślna ścieżka serwowania to frontend/dist, którą można zmienić przez VIPNET_WEB_DIR. Ustal profil pomiaru odpowiedni do możliwości hosta. VIPNET_CAPACITY_BPS umożliwia ograniczenie łącznej szybkości strumieni. Jeden proces węzła obsługuje jedną rezerwację naraz. Aplikacja Windows może użyć adresu instalacji wskazanego przez VIPNET_DESKTOP_ORIGIN.

Odczyt GET /api/v1/health potwierdza wersję API i stan migracji. Dla samodzielnego odbioru wykonaj autoryzowany pomiar swoim klientem i sprawdź jego raport w odpowiednim panelu. [Opis pomiarów](../../measurement-node/README.md)
