# Panel operatora

Wdrożona wersja 0.5.0 ma stronę pobierania, logowanie klienta na `/klient` i administratora organizacji na `/admin`. Oba widoki pobierają sesje z PostgreSQL za pośrednictwem autoryzowanego API. Można filtrować stronami według stanu, otworzyć raport, wydrukować go lub pobrać JSON. Administrator widzi też dane komputera i statystyki MTR według faz i skoków. Kod klienta pochodzi z aplikacji Windows. Kod operatora wydaje administrator instalacji. [Instrukcja klienta](../deploy/windows-portable.md)

Zbuduj pliki statyczne na Node.js 24 z pnpm 11, używając `pnpm install --frozen-lockfile` i `pnpm run build` w tym katalogu. Budowa obejmuje TypeScript, Vue i kontrolę polskich znaków w wydawanym JavaScripcie.

## Dalszy plan panelu operatorskiego

Projekt v0.5.0 zakłada Vue 3, TypeScript, Vite, polskie komunikaty w katalogach tłumaczeń i wersję w stopce. Nawigacja obejmie Dashboard, Sesje, Abonenci, MTR, LAN, Przepustowość, Hosty, Agenci, Incydenty, Raporty, Integracje, Ustawienia i Audyt.

Lista sesji użyje paginacji i sortowania serwerowego z dodatkowym kluczem UUID. Rozwinięcie rekordu pobierze szczegóły w granicach zakresu operatora. Analizator pokaże statystyki, próbki, wykresy RTT i strat, źródła ASN, różnice tras i wersje reguł. Projekcja publiczna raportu będzie miała własną listę dozwolonych pól. Na etapie 0 interfejsem wykonywalnym jest CLI Windows.
