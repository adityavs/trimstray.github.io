---
layout: post
title: 'NGINX: Jak poprawnie obsługiwać nagłówki?'
date: 2018-12-17 21:04:12
categories: [PL, http, nginx, best-practices]
tags: [publications]
comments: false
favorite: false
seo:
  date_modified: 2020-01-31 13:18:24 +0100
---

Nagłówki to jedna z najistotniejszych rzeczy podczas komunikacji między klientem a serwerem. NGINX dostarcza kilka sposobów ich obsługi, lecz nieodpowiednie użycie któregoś z nich może spowodować poważne problemy (w tym np. naruszenie zasada bezpieczeństwa!).

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
