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
