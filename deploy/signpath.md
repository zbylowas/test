# Podpis Authenticode dla publicznej kompilacji Windows

Twórcą projektu jest **vip-net.pl**. Podpis w modelu open source, po przyjęciu projektu, będzie wystawiany w imieniu **SignPath Foundation**. Instalacja aplikacji GitHub i uprawnienia wydawnicze dotyczą repozytorium zbylowas/test. [Warunki fundacji](https://signpath.org/terms)

## Przypisanie ról

- Autorzy zmian, recenzenci i zatwierdzający podpisy działają pod kontrolą opiekuna repozytorium [zbylowas](https://github.com/zbylowas). Opiekun przypisuje konkretne konta do ról w organizacji SignPath.
- Opiekunowie włączają MFA dla GitHuba i SignPath. Każde żądanie podpisu wymaga ręcznego zatwierdzenia w SignPath.
- [Polityka prywatności klienta](../README.md#dane-pomiarowe).

## Konfiguracja po akceptacji projektu

1. W panelu SignPath połącz projekt z zaufanym systemem GitHub.com. W ustawieniach pochodzenia dopuść repozytorium zbylowas/test, gałąź main i workflow .github/workflows/stage-0.yml. Włącz ręczne zatwierdzanie żądań podpisu. [Integracja GitHub](https://docs.signpath.io/trusted-build-systems/github)
2. Wgraj [konfigurację artefaktu](signpath-artifact.xml). Wymusza ona nazwę produktu, oznaczenie twórcy i tę samą wersję obu podpisywanych EXE.
3. W GitHub Environments utwórz signpath-release. Ustaw SECRET SIGNPATH_API_TOKEN z uprawnieniem do składania żądań dla przeznaczonej do tego polityki. Dodaj zmienne SIGNPATH_ORGANIZATION_ID, SIGNPATH_PROJECT_SLUG, SIGNPATH_SIGNING_POLICY_SLUG, SIGNPATH_ARTIFACT_CONFIGURATION_SLUG i SIGNPATH_PUBLISHER_SHA256. Ostatnia zmienna to 64-znakowy SHA-256 certyfikatu wydawcy w formacie DER, zweryfikowanego w panelu SignPath.
4. Uruchom ręcznie workflow **Windows and PostgreSQL acceptance** na gałęzi **main** z włączonym **sign_windows**. Po testach CI wysyła identyfikator utworzonego artefaktu do SignPath. Po zatwierdzeniu GitHub odbiera podpisane pliki.
5. Po sprawdzeniu zaufania Authenticode, znacznika czasu, odcisku wydawcy i metadanych PE workflow udostępnia artefakt windows-x64-signed z sumami SHA-256. Z niego należy pobrać EXE do wydania.

## Aktualizacje istniejących instalacji

Publiczny artefakt pozwala uruchomić aplikację z własnym adresem serwera podanym poza binarium. Aktualizator istniejącego kanału dystrybucji sprawdza odrębny podpis manifestu przypiętym kluczem projektu. Przed podmianą wydania na portalu trzeba przygotować konfigurację zgodną z kanałem, wygenerować manifest dla podpisanych bajtów EXE i wykonać próbę aktualizacji poprzedniej wersji. Podpis Authenticode sam w sobie potwierdza wydawcę EXE i integralność pliku.

[Zgłoszenie do SignPath Foundation](https://signpath.org/apply)
