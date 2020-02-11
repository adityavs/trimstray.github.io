---
layout: post
title: 'NGINX: Ukryte pliki i katalogi'
date: 2018-08-17 21:02:30
categories: [PL, http, nginx, best-practice]
tags: [publications]
comments: false
favorite: false
seo:
  date_modified: 2020-02-11 09:19:12 +0100
---

Ukryte pliki i katalogi nigdy nie powinny być publicznie dostępne - czasami krytyczne dane są publikowane podczas wdrażania aplikacji. Jeśli używasz systemu konstroli wersji, zdecydowanie powinieneś zabronić dostępu (dając mniej informacji atakującym) do krytycznych ukrytych plików/katalogów, takich jak `.git` lub `.svn`, aby zapobiec np. ujawnieniu kodu źródłowego twojej aplikacji.

Wrażliwe zasoby zawierają elementy, z których atakujący mogą skorzystać w celu pełnego odtworzenia kodu źródłowego, znalezienia błędów w aplikacji, luk w zabezpieczeniach czy zapisanych haseł (tak, to też się niestety zdarza...).

Jeśli chodzi o metodę odmowy to moim zdaniem kod 403 (lub nawet 404, jak sugeruje [RFC 2616 - 403 Forbidden](https://tools.ietf.org/html/rfc2616#section-10.4.4) <sup>[IETF]</sup> dla celów nieujawniania informacji) jest mniej podatny na błędy, jeśli wiesz, że zasób nie powinien być w żadnym wypadku dostępny za pośrednictwem http).

Dodatkowa uwaga:

Jeśli w danej lokalizacji używasz wyrażeń regularnych, NGINX stosuje je w kolejności ich pojawienia się w pliku konfiguracyjnym. Możesz także użyć modyfikatora `^~`, który powoduje, że blok lokalizacji prefiksu ma pierwszeństwo przed dowolnym blokiem lokalizacji wyrażeń regularnych na tym samym poziomie.

NGINX przetwarza każdy request etapami (w tak zwanych fazach). Dyrektywa `return` pochodzi z modułu przepisywania, a dyrektywa `deny` pochodzi z modułu dostępu. Moduł przepisywania jest przetwarzany w fazie `NGX_HTTP_REWRITE_PHASE` (dla `return` w kontekście lokalizacji) a moduł dostępu jest przetwarzany w fazie `NGX_HTTP_ACCESS_PHASE`. Faza przepisywania (gdzie rezyduje `return`) następuje przed fazą dostępu (gdzie działa dyrektywa `deny`), w ten sposób powrót zatrzymuje przetwarzanie żądania i zwraca 301 w fazie przepisywania.

`deny all` ma takie same konsekwencje, ale pozostawia możliwości wpadek. Problem został zilustrowany w [tej](https://serverfault.com/questions/748320/protecting-a-location-by-ip-while-applying-basic-auth-everywhere-else/748373#748373) odpowiedzi, sugerując, że nie należy używać `satisfy` + `allow` + `deny` na poziomie kontekstu `server {...}` z powodu dziedziczenia.

Z drugiej strony, zgodnie z dokumentacją NGINX: moduł `ngx_http_access_module` umożliwia ograniczenie dostępu do niektórych adresów klientów. Mówiąc dokładniej, nie można ograniczyć dostępu do innego modułu (`return` jest częściej używany, gdy chcesz zwrócić inne kody, a nie blokować dostęp np. do danego zasobu).

Przykład:

- nie zalecana konfiguracja:

```nginx
if ($request_uri ~ "/\.git") {

  return 403;

}
```

- zalecana konfiguracja:

```nginx
# 1) Przechwytuj tylko ukryte pliki (bez rozszerzeń):
# Przykład: /foo/bar/.git ale nie /foo/bar/file.git
location ~ /\.git {

  return 403;

}

# 2) Przechwytuj wszystkie ukryte pliki/katalogi oraz rozszerzenia:
# Przykład: /foo/bar/.git i /foo/bar/file.git
location ~* ^.*(\.(?:git|svn|htaccess))$ {

  deny all;

}
```

- najbardziej zalecana konfiguracja:

```nginx
# Przechwytuj wszystkie ukryte pliki/katalogi z wyjątkiem .well-known:
# Przykład: /foo/bar/.git ale nie /foo/bar/file.git
location ~ /\.(?!well-known\/) {

  deny all;
  access_log /var/log/nginx/hidden-files-access.log main;
  error_log /var/log/nginx/hidden-files-error.log warn;

}
```

- dodatkowo dla plików zawierających rozszerzenia:

```nginx
# Przechwytuj wszystkie ukryte pliki/katalogi oraz rozszerzenia:
# Przykład: /foo/bar/.git i /foo/bar/file.git
location ~* ^.*(\.(?:git|svn|hg|bak|bckp|save|old|orig|original|test|conf|cfg|dist|in[ci]|log|sql|mdb|sw[op]|htaccess|php#|php~|php_bak|aspx?|tpl|sh|bash|bin|exe|dll|jsp|out|cache|))$ {

  # Warto użyć także reguł rate-limitujących:
  # w kontekście server: limit_req_zone $binary_remote_addr zone=per_ip_5r_s:5m rate=5r/s;
  limit_req zone=per_ip_5r_s;

  deny all;
  access_log /var/log/nginx/restricted-files-access.log main;
  access_log /var/log/nginx/restricted-files-error.log main;

}
```
