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

# 1) Zdefiniuj dyrektywy nasłuchiwania za pomocą pary adres:port

NGINX tłumaczy wszystkie niepełne dyrektywy `listen` zastępując brakujące wartości ich wartościami domyślnymi. Co więcej, oceni dyrektywę `server_name` tylko wtedy, gdy będzie musiał rozróżnić bloki serwera pasujące do tego samego poziomu w dyrektywie `listen`. Ustawienie pary **adres:port** zapobiega subtelnym błędom, które mogą być trudne do debugowania.

Na przykład, jeżeli mamy w konfiguracji dyrektywę `listen *:80` i kilka bloków `server`, w których zdiefiniowana jest ta dyrektywa, zostanie ona uzupełniona i w wyniku będzie wyglądać tak: `listen 0.0.0.0:80`. Następnie dodając w którymś miejscu konfiguracji `listen 192.168.50.2:80` wszystkie bloki `server` zawierające pierwszą dyrektywę `listen` (uzupełnioną przez NGINX) będą miały niższy priorytet i nie będą przetwarzane (request z nagłówkiem `Host` niepasujący do `server_name` wpadnie do dyrektywy `listen` oznaczonej jako `default_server` - jawnie wskazanej, lub jeśli nie, pierwszej w konfiguracji).

Ponadto brak adresu IP oznacza powiązanie ze wszystkimi adresami IP w systemie, co może powodować wiele problemów i co do zasady jest bardzo złą praktyką – zaleca się konfigurowanie tylko minimalnego dostępu do sieci dla usług.

Przykład:

- testowy request:

```bash
$ curl -Iks http://api.random.com
```

- konfiguracja po stronie serwera:

```nginx
server {

  # Ten blok będzie przetwarzany!
  listen 192.168.252.10; # --> 192.168.252.10:80

  ...

}

server {

  # Ponieważ NGINX uzupełni adres IP wartością poniżej,
  # która ma niższy priorytet niż jasne wskazanie
  # adresu.
  listen 80; # --> *:80 --> 0.0.0.0:80
  server_name api.random.com;

  ...

}
```

# 2) Zapobiegaj przetwarzaniu żądań przy użyciu niezdefiniowanych nazw serwerów

Zastosowanie tej reguły chroni przed błędami konfiguracji, np. przekazywanie ruchu do niepoprawnych backendów, omijając filtry takie jak ACL lub WAF. Problem można łatwo rozwiązać, tworząc domyślny "fałszywy" vhost, który przechwytuje wszystkie żądania z nierozpoznanymi nagłówkami hosta.

Jak wiemy, nagłówek `Host` informuje serwer, którego hosta wirtualnego ma użyć (jeśli jest skonfigurowany). Możesz nawet mieć tego samego wirtualnego hosta, używając kilku aliasów (= domeny i symbole wieloznaczne). Nagłówek ten można również modyfikować, dlatego ze względów bezpieczeństwa i czystości dobrą praktyką jest odrzucanie żądań bez hosta lub z hostami nie skonfigurowanymi w żadnym vhoście. Zgodnie z tym NGINX powinien zapobiegać przetwarzaniu żądań z nieokreślonymi nazwami serwerów (także na adres IP).

Rozwiązaniem problemu jest ustawienie dyrektywy `listen` z parametrem `default_server`. Jeśli żadna z dyrektyw `listen` nie ma parametru `default_server`, wówczas pierwszy serwer z parą **adres:port** będzie domyślnym serwerem dla tej pary (oznacza to, że NGINX zawsze ma domyślny serwer).

Jeśli ktoś zgłosi żądanie przy użyciu adresu IP zamiast nazwy serwera, pole nagłówka żądania `Host` będzie zawierało adres IP i żądanie może zostać przetworzone przy użyciu adresu IP jako nazwy serwera.

W rzeczywistości `default_server` nie potrzebuje instrukcji `server_name`, ponieważ pasuje do wszystkiego, do czego inne bloki serwera nie pasują jawnie.

Jeśli nie można znaleźć serwera z pasującym parametrem `listen` i `server_name`, NGINX użyje serwera domyślnego. Jeśli konfiguracje są rozłożone na wiele plików, kolejność oceny będzie niejednoznaczna, dlatego należy wyraźnie zaznaczyć domyślny serwer.

Przykład:

```nginx
# Umieść na początku konfiguracji:
server {

  # Dla obsługi SSL pamiętaj o odpowiedniej konfiguracji;
  # Dodając default_server to dyrektywy listen w kontekście server mówisz,
  # żeby NGINX traktował ten blok jako domyślny:
  listen 10.240.20.2:443 default_server ssl;

  # Za pomocą poniższej dyrektywy obsługujemy:
  #   - niepoprawne domeny (nie obsługiwane przez NGINX)
  #   - requesty bez nagłowka "Host"
  # Pamiętaj, że wartość default_server w dyrektywie server_name nie jest wymagany,
  # co więcej dyrektywy server_name może nie być w ogóle (a jeśli jest
  # może zawierać cokolwiek).
  server_name _ "" default_server;

  # Dodatkowo ustawiamy limitowanie:
  limit_req zone=per_ip_5r_s;

  ...

  # Zamykamy połączenie wewnętrznie (bez zwracania odpowiedzi do klienta):
  return 444;

  # Można także zaserwować klientowi stronę statyczną lub przekierować go
  # w inny miejsce:
  # location / {
  #
  #   static file (error page):
  #     root /etc/nginx/error-pages/404;
  #   or redirect:
  #     return 301 https://badssl.com;
  #
  # }

  # Pamiętaj o logowaniu takich akcji:
  access_log /var/log/nginx/default-access.log main;
  error_log /var/log/nginx/default-error.log warn;

}

server {

  listen 10.240.20.2:443 ssl;

  server_name example.com;

  ...

}

server {

  listen 10.240.20.2:443 ssl;

  server_name domain.org;

  ...

}
```

# 3) Obsługuj nagłówki HTTP za pomocą dyrektyw add_header i proxy_*_ w poprawny sposób

Pamiętajmy, że dyrektywa `add_header` działa w zakresach `if`, `location`, `server` i `http`. Dyrektywy `proxy_*_` działają w zakresie `location`, `server` i `http`. Dyrektywy te są dziedziczone z poprzedniego poziomu tylko wtedy, gdy na bieżącym poziomie nie zdefiniowano dyrektyw nagłówka `add_header` lub `proxy_*_`.

Jeśli używasz ich w wielu kontekstach, używane są tylko najniższe wystąpienia. Jeśli więc określisz to w kontekście serwera i lokalizacji (nawet jeśli ukryjesz inny nagłówek, ustawiając tę ​​samą dyrektywę i tę samą wartość), użyty zostanie tylko jeden z nich w bloku lokalizacji. Aby zapobiec tej sytuacji, powinieneś zdefiniować wspólny fragment konfiguracji i dołączyć go tylko w miejscu, do którego chcesz wysłać te nagłówki. To najbardziej przewidywalne rozwiązanie.

Moim zdaniem również ciekawym rozwiązaniem jest użycie pliku dołączania z globalnymi nagłówkami i dodanie go do kontekstu `http` (jednak wtedy niepotrzebnie powielasz reguły). Następnie powinieneś również skonfigurować inny plik dołączania z konfiguracją specyficzną dla serwera/domeny (ale zawsze z globalnymi nagłówkami! Musisz powtórzyć go w najniższych kontekstach) i dodać go do kontekstu serwera/lokalizacji. Jest to jednak nieco bardziej skomplikowane i w żaden sposób nie gwarantuje spójności.

Istnieją dodatkowe rozwiązania tego problemu, takie jak użycie alternatywnego modułu (`headers-more-nginx-module`) do zdefiniowania określonych nagłówków w blokach `server` lub `location`. Nie wpływa na powyższe dyrektywy.

Dodatkowo istnieje świetne wyjaśnienie problemu:

  > _Therefore, let’s say you have an http block and have specified the add_header directive within that block. Then, within the http block you have 2 server blocks - one for HTTP and one for HTTPs._

  > _Let’s say we don’t include an add_header directive within the HTTP server block, however we do include an additional add_header within the HTTPs server block. In this scenario, the add_header directive defined in the http block will only be inherited by the HTTP server block as it does not have any add_header directive defined on the current level. On the other hand, the HTTPS server block will not inherit the add_header directive defined in the http block._

Przykład:

- nie zalecana konfiguracja:

```nginx
http {

  # W kontekście http ustawiamy:
  #   - 'FooX barX' (add_header)
  #   - 'Host $host' (proxy_set_header)
  #   - 'X-Real-IP $remote_addr' (proxy_set_header)
  #   - 'X-Forwarded-For $proxy_add_x_forwarded_for' (proxy_set_header)
  #   - 'X-Powered-By' (proxy_hide_header)

  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_hide_header X-Powered-By;

  add_header FooX barX;

  ...

  server {

    server_name example.com;

    # W kontekście server ustawiamy:
    #   - 'FooY barY' (add_header)
    #   - 'Host $host' (proxy_set_header)
    #   - 'X-Real-IP $remote_addr' (proxy_set_header)
    #   - 'X-Forwarded-For $proxy_add_x_forwarded_for' (proxy_set_header)
    #   - 'X-Powered-By' (proxy_hide_header)
    # Tym samym nie ustawiamy:
    #   - 'FooX barX' (add_header)

    add_header FooY barY;

    ...

    location / {

      # W kontekście location ustawiamy:
      #   - 'Foo bar' (add_header)
      #   - 'Host $host' (proxy_set_header)
      #   - 'X-Real-IP $remote_addr' (proxy_set_header)
      #   - 'X-Forwarded-For $proxy_add_x_forwarded_for' (proxy_set_header)
      #   - 'X-Powered-By' (proxy_hide_header)
      #   - headers from ngx_headers_global.conf
      # Tym samym nie ustawiamy:
      #   - 'FooX barX' (add_header)
      #   - 'FooY barY' (add_header)

      include /etc/nginx/ngx_headers_global.conf;
      add_header Foo bar;

      ...

    }

    location /api {

      # W kontekście location ustawiamy:
      #   - 'FooY barY' (add_header)
      #   - 'Host $host' (proxy_set_header)
      #   - 'X-Real-IP $remote_addr' (proxy_set_header)
      #   - 'X-Forwarded-For $proxy_add_x_forwarded_for' (proxy_set_header)
      #   - 'X-Powered-By' (proxy_hide_header)
      # Tym samym nie ustawiamy:
      #   - 'FooX barX' (add_header)

      ...

    }

  }

  server {

    server_name a.example.com;

    # W kontekście server ustawiamy:
    #   - 'FooY barY' (add_header)
    #   - 'Host $host' (proxy_set_header)
    #   - 'X-Real-IP $remote_addr' (proxy_set_header)
    #   - 'X-Powered-By' (proxy_hide_header)
      # Tym samym nie ustawiamy:
    #   - 'FooX barX' (add_header)
    #   - 'X-Forwarded-For $proxy_add_x_forwarded_for' (proxy_set_header)

    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_hide_header X-Powered-By;

    add_header FooY barY;

    ...

    location / {

      # W kontekście location ustawiamy:
      #   - 'FooY barY' (add_header)
      #   - 'X-Powered-By' (proxy_hide_header)
      #   - 'Accept-Encoding ""' (proxy_set_header)
      # Tym samym nie ustawiamy:
      #   - 'FooX barX' (add_header)
      #   - 'Host $host' (proxy_set_header)
      #   - 'X-Real-IP $remote_addr' (proxy_set_header)
      #   - 'X-Forwarded-For $proxy_add_x_forwarded_for' (proxy_set_header)

      proxy_set_header Accept-Encoding "";

      ...

    }

  }

}
```

- następnie przykład poprawnej i zalecanej konfiguracji:

```nginx
# Poniższe dyrektywy przechowujemy w zewnętrznym pliku, np. proxy_headers.conf:
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_hide_header X-Powered-By;

http {

  server {

    server_name example.com;

    ...

    location / {

      include /etc/nginx/proxy_headers.conf;
      include /etc/nginx/ngx_headers_global.conf;
      add_header Foo bar;

      ...

    }

    location /api {

      include /etc/nginx/proxy_headers.conf;
      include /etc/nginx/ngx_headers_global.conf;
      add_header Foo bar;

      more_set_headers 'FooY: barY';

      ...

    }

  }

  server {

    server_name a.example.com;

    ...

    location / {

      include /etc/nginx/proxy_headers.conf;
      include /etc/nginx/ngx_headers_global.conf;
      add_header Foo bar;
      add_header FooX barX;

      ...

    }

  }

  server {

    server_name b.example.com;

    ...

    location / {

      include /etc/nginx/proxy_headers.conf;
      include /etc/nginx/ngx_headers_global.conf;
      add_header Foo bar;

      ...

    }

  }

}
```

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
