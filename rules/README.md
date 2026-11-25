# Interpretacja MTR · reguły 0.2.0

Wejście to zwalidowane próbki jednej sesji, celu, rodziny adresowej, protokołu i fazy. Worker grupuje także port TCP. Dla starszych próbek TCP bez portu raport podaje null. Historia reguł ICMP 0.1.0 jest dostępna w module `rules.v010`. Niepełne serie pozostają w historii. Dane testowe w fixtures/mtr-cases.json to jawnie syntetyczne przypadki jednostkowe.

| Miara per TTL | Definicja |
| --- | --- |
| Snt / Rcv / Loss | Snt obejmuje próby z rozstrzygniętym wynikiem sieciowym, w tym timeout. Rcv obejmuje każdy odebrany i sklasyfikowany komunikat, także unreachable. Loss = 100 × (Snt − Rcv) / Snt. Przy Snt = 0 wartość jest null. Liczba unavailable jest osobna, stan transmisji takich prób może być nieznany. |
| Last / Best / Avg / Worst | RTT ostatniej próby według numeru rundy (null przy braku odpowiedzi), minimum, średnia arytmetyczna i maksimum znanych RTT. |
| StDev / P50 / P95 / P99 | Odchylenie standardowe populacji i empiryczne percentyle nearest rank, indeks ceil(p × n) w szeregu rosnącym liczonym od 1. Brak odpowiedzi daje null. |
| mean_abs_delta_ms | Średnia wartość bezwzględna różnic RTT między kolejnymi numerami prób z odpowiedzią z tego samego adresu na danym TTL. Luka lub zmiana adresu rozdziela serię. Brak par daje null. |

Pięć prób to dolna granica reguł heurystycznych, nie gwarancja istotności statystycznej. Liczby strat na pośrednim TTL opisują brak odpowiedzi na próbę skierowaną do tej głębokości. Wnioski o ograniczaniu ICMP wymagają pełnej odpowiedzi celu w tych samych rundach. Cisza na końcu przy ograniczonym TTL oznacza niepotwierdzone dotarcie. Więcej niż jeden adres na TTL to obserwacja zgodna m.in. z ECMP i zmianą trasy. Asymetria, filtrowanie, kolejkowanie odpowiedzi i wybór drogi powrotnej ograniczają przypisanie przyczyny.

Każda diagnoza ma rule_id, version, severity, confidence, evidence, limitations i recommended_tests. W serii TCP odpowiedź connected lub refused liczy się do Rcv. Nawet poprawna odpowiedź TCP może pochodzić z urządzenia pośredniczącego.

## Warunki rozpoznań

| Obserwacja | Wymagane dowody |
| --- | --- |
| Cisza lub ograniczanie ICMP | Pięć lub więcej wysłanych prób, zero albo część odpowiedzi routera i komplet odpowiedzi celu w tych samych rundach |
| Braki utrzymujące się do celu | Co najmniej dwie te same rundy z timeoutem na kolejnych TTL włącznie z rozpoznanym TTL celu |
| Opóźnienie LAN, trwały skok RTT, wysoki pojedynczy hop | Stabilni respondenci, pełne odpowiedzi, co najmniej pięć rund i 80% rund ze skokiem co najmniej 20 ms. Reguła LAN odnosi się do pierwszego widocznego TTL |
| Pętla, zmiana trasy, ECMP | A–B–A–B w tych samych co najmniej pięciu rundach, dwa kolejne stabilne odcinki adresów lub co najmniej cztery przeplatane odcinki na jednym TTL |
| IPv6 | Kod lokalnego błędu trasy lub nieudany pomiar do potwierdzonego adresu usługi przy działającym odpowiedniku IPv4 i porównywalnym zakresie prób |
| Rozbieżność ICMP/TCP | Wspólny cel, faza, rundy i kontrolna głębokość. Różnica wynosi co najmniej dwie odpowiedzi. Port 443 musi wynikać z zapisu |
| Możliwa asymetria | Kontrolowany pomiar zwrotny, zgodne końce, dwa pełne stabilne przebiegi w oknie pięciu minut oraz różne uporządkowane listy pośrednich adresów |
| Możliwe kolejkowanie pod obciążeniem | Wzrost mediany celu o co najmniej 20 ms przy zadeklarowanej fazie ruchu, odzyskanie poziomu bazowego z odchyleniem poniżej 10 ms i zgodna trasa w trzech kolejnych oknach |
| Styk sieci | Utrzymujący się skok RTT na granicy dwóch sieci wskazanych przez operatora w pliku z mapowaniem adresów |
| Niedostępność i niepełne dane | Powtarzalny jawny komunikat unreachable, osobne rozpoznanie dla niepotwierdzonego celu oraz informacja o niewystarczającej liczbie prób |

Porównania kontekstowe uruchamia lokalnie `python -m rules.report PLIK.ndjson` z opcjami `--dual-stack-pair IPv4 IPv6`, `--networks MAPPING.json` lub `--reverse-dir KATALOG`. Worker oblicza statystyki i diagnozy wynikające z samej sesji. Każda diagnoza zawiera ograniczenia i dalszy test. Dane surowe i mapowania używane przez operatora są prywatne.
