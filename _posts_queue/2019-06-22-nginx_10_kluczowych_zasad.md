---
layout: post
title: 'NGINX: 10 kluczowych zasad'
date: 2019-06-22 09:17:04
categories: [PL, http, nginx, best-practices]
tags: [publications]
comments: false
favorite: false
seo:
  date_modified: 2020-01-31 13:18:24 +0100
---

Istnieje wiele rzeczy, które możesz zrobić, aby ulepszyć konfigurację serwera NGINX. W tym wpisie przedstawię 10 zasad, moim zdaniem bardzo ważnych, które bezwzględnie należy stosować podczas konfiguracji. Niektóre są pewnie oczywiste, inne może nie.

# 4) Używaj dyrektywy return zamiast rewrite dla przekierowań

To prosta zasada. Możliwość przepisywania adresów URL w NGINX jest niezwykle potężną i ważną funkcją. Technicznie możesz użyć obu opcji, ale moim zdaniem powinieneś używać bloków serwera z wykorzystaniem modułu przepisywania stosując dyrektywę `return`, ponieważ są one znacznie szybsze niż ocena wyrażeń regularnych, np. poprzez bloki lokalizacji.

Dla każdego żądania NGINX musi przetworzyć i rozpocząć wyszukiwanie. Dyrektywa `return` zatrzymuje przetwarzanie (bezpośrednio zatrzymuje wykonywanie) i zwraca określony kod klientowi. Jest to preferowane w dowolnym kontekście.

Dodatkowo jest to prostsze i szybsze, ponieważ NGINX przestaje przetwarzać żądanie (i nie musi przetwarzać wyrażeń regularnych). Co więcej, możesz podać kod z serii 3xx.

Jeśli masz scenariusz, w którym musisz zweryfikować adres URL za pomocą wyrażenia regularnego lub musisz przechwycić elementy w oryginalnym adresie URL (które oczywiście nie znajdują się w odpowiedniej zmiennej NGINX), wtedy powinieneś użyć przepisania.

Przykład:

- nie zalecana konfiguracja:

```nginx
server {

  ...

  location / {

    try_files $uri $uri/ =404;

    rewrite ^/(.*)$ https://example.com/$1 permanent;

  }

  ...

}
```

- zalecana konfiguracja:

```nginx
server {

  ...

  location / {

    try_files $uri $uri/ =404;

    return 301 https://example.com$request_uri;

  }

  ...

}
```

# 5) Jeśli to możliwe, używaj dokładnych nazw w dyrektywie nazwa_serwera

Dokładne nazwy, nazwy symboli wieloznacznych rozpoczynające się od gwiazdki i nazwy symboli wieloznacznych kończące się gwiazdką są przechowywane w trzech tablica skrótów powiązanych z portami nasłuchiwania.

Najpierw przeszukiwana jest dokładna tablica skrótów nazw. Jeśli nazwa nie zostanie znaleziona, przeszukiwana jest tablica skrótów z nazwami symboli wieloznacznych rozpoczynającymi się od gwiazdki. Jeśli nie ma tam nazwy, przeszukiwana jest tablica skrótów z nazwami symboli wieloznacznych kończącymi się gwiazdką.

Przeszukiwanie tablicy skrótów nazw symboli wieloznacznych jest wolniejsze niż wyszukiwanie tablicy skrótów nazw dokładnych, ponieważ nazwy są wyszukiwane według części domeny.

Wyrażenia regularne są testowane sekwencyjnie, dlatego są najwolniejszą metodą i nie są skalowalne. Z tych powodów lepiej jest używać dokładnych nazw tam, gdzie to możliwe.

Przykład:

- nie zalecana konfiguracja:

```nginx
server {

  listen 192.168.252.10:80;

  server_name .example.org;

  ...

}
```

- zalecana konfiguracja:

```nginx
server {

  listen 192.168.252.10:80;

  server_name example.org www.example.org *.example.org;

  ...

}
```

# 6) Aktywuj pamięć podręczną dla połączeń z serwerami nadrzędnymi

Ideą mechanizmu `Keepalive` jest zajęcie się opóźnieniami w nawiązywaniu połączeń TCP w sieciach o dużych opóźnieniach. Ta pamięć podręczna połączeń jest przydatna w sytuacjach, gdy NGINX musi stale utrzymywać pewną liczbę otwartych połączeń z serwerem z warstwy backendu.

Połączenia `Keep-Alive` mogą mieć znaczący wpływ na wydajność, zmniejszając obciążenie procesora i sieci potrzebne do otwierania i zamykania połączeń. Z włączonym podtrzymywaniem HTTP w serwerach upstream NGINX zmniejsza opóźnienia, a tym samym poprawia wydajność i zmniejsza prawdopodobieństwo, że zabraknie portów efemerycznych.

Może to znacznie zmniejszyć liczbę nowych połączeń TCP, ponieważ NGINX może teraz ponownie wykorzystywać swoje istniejące połączenia (utrzymywanie aktywności) na jednym etapie przesyłania danych.

Jeśli twój serwer nadrzędny obsługuje `Keep-Alive` (jest to warunek konieczny) w swojej konfiguracji, NGINX będzie teraz ponownie używał istniejących połączeń TCP bez tworzenia nowych. Może to znacznie zmniejszyć liczbę gniazd w połączeniach `TIME_WAIT` TCP na zajętych serwerach (mniej pracy dla systemu operacyjnego w celu ustanowienia nowych połączeń, mniej pakietów w sieci).

Połączenia Keep-Alive są obsługiwane tylko od HTTP/1.1.

Przykład:

```nginx
# W kontekście upstream:
upstream backend {

  # Ustawia maksymalną liczbę bezczynnych połączeń
  # podtrzymujących połączenie z serwerami nadrzędnymi,
  # które są zachowane w pamięci podręcznej każdego procesu roboczego.
  keepalive 16;

}

# W kontekście server/location:
server {

  ...

  location / {

    # NGINX domyślnie komunikuje się tylko za pomocą protokołu HTTP/1
    # z serwerami, keepalive jest włączony tylko w HTTP/1.1:
    proxy_http_version 1.1;

    # Usuń nagłówek połączenia, jeśli klient go wysyła,
    # w celu zamknięcia połączenia podtrzymującego:
    proxy_set_header Connection "";

    ...

  }

}
```

# 7) Chroń wrażliwe zasoby takie jak ukryte pliki i katalogi

Ukryte katalogi i pliki nigdy nie powinny być publicznie dostępne - czasami krytyczne dane są publikowane podczas wdrażania aplikacji. Jeśli używasz systemu konstroli wersji, zdecydowanie powinieneś upuścić dostęp (dając mniej informacji atakującym) do krytycznych ukrytych katalogów/plików, takich jak `.git` lub `.svn`, aby zapobiec ujawnieniu kodu źródłowego twojej aplikacji.

Wrażliwe zasoby zawierają elementy, z których osoby nadużywające mogą korzystać w celu pełnego odtworzenia kodu źródłowego używanego przez witrynę i szukania błędów, luk w zabezpieczeniach i ujawnionych haseł.

Jeśli chodzi o metodę odmowy to moim zdaniem kod 403 (lub nawet 404, jak sugeruje [RFC 2616 - 403 Forbidden](https://tools.ietf.org/html/rfc2616#section-10.4.4) <sup>[IETF]</sup> dla celów nieujawniania informacji) jest mniej podatny na błędy, jeśli wiesz, że zasób nie powinien być w żadnym wypadku dostępny za pośrednictwem http, nawet jeśli „autoryzowane” w ogólnym kontekście.

Dodatkowa uwaga:

Jeśli używasz lokalizacji z wyrażeniami regularnymi, NGINX stosuje je w kolejności ich pojawienia się w pliku konfiguracyjnym. Możesz także użyć modyfikatora `^~`, który powoduje, że blok lokalizacji prefiksu ma pierwszeństwo przed dowolnym blokiem lokalizacji wyrażeń regularnych na tym samym poziomie.

NGINX przetwarza każdy request etapami (w tak zwanych fazach). Dyrektywa `return` pochodzi z modułu przepisywania, a dyrektywa `deny` pochodzi z modułu dostępu. Moduł przepisywania jest przetwarzany w fazie `NGX_HTTP_REWRITE_PHASE` (dla `return` w kontekście lokalizacji), moduł dostępu jest przetwarzany w fazie `NGX_HTTP_ACCESS_PHASE`, faza przepisywania (gdzie należy `return`) następuje przed fazą dostępu (gdzie działa dyrektywa `deny`), w ten sposób powrót zatrzymuje przetwarzanie żądania i zwraca 301 w fazie przepisywania.

`deny all` ma takie same konsekwencje, ale pozostawia możliwości wpadek. Problem został zilustrowany w tej odpowiedzi, sugerując, że nie należy używać `satisfy` + `allow` + `deny` na poziomie kontekstu `server {...}` z powodu dziedziczenia.

Z drugiej strony, zgodnie z dokumentacją NGINX: moduł `ngx_http_access_module` umożliwia ograniczenie dostępu do niektórych adresów klientów. Mówiąc dokładniej, nie można ograniczyć dostępu do innego modułu (`return` jest częściej używany, gdy chcesz zwrócić inne kody, a nie blokować dostęp).

Przykład:

- nie zalecana konfiguracja:

```nginx
if ($request_uri ~ "/\.git") {

  return 403;

}
```

- zalecana konfiguracja:

```nginx
# 1) Catch only file names (without file extensions):
# Example: /foo/bar/.git but not /foo/bar/file.git
location ~ /\.git {

  return 403;

}

# 2) Catch file names and file extensions:
# Example: /foo/bar/.git and /foo/bar/file.git
location ~* ^.*(\.(?:git|svn|htaccess))$ {

  deny all;

}
```

- najbardziej zalecana konfiguracja:

```nginx
# Catch all . directories/files excepted .well-known (without file extensions):
# Example: /foo/bar/.git but not /foo/bar/file.git
location ~ /\.(?!well-known\/) {

  deny all;
  access_log /var/log/nginx/hidden-files-access.log main;
  error_log /var/log/nginx/hidden-files-error.log warn;

}
```

- dodatkowo dla plików zawierających rozszerzenia:

```nginx
# Catch file names and file extensions:
# Example: /foo/bar/.git and /foo/bar/file.git
location ~* ^.*(\.(?:git|svn|hg|bak|bckp|save|old|orig|original|test|conf|cfg|dist|in[ci]|log|sql|mdb|sw[op]|htaccess|php#|php~|php_bak|aspx?|tpl|sh|bash|bin|exe|dll|jsp|out|cache|))$ {

  # Use also rate limiting:
  # in server context: limit_req_zone $binary_remote_addr zone=per_ip_5r_s:5m rate=5r/s;
  limit_req zone=per_ip_5r_s;

  deny all;
  access_log /var/log/nginx/restricted-files-access.log main;
  access_log /var/log/nginx/restricted-files-error.log main;

}
```
