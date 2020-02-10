---
layout: post
title: 'NGINX: Zapobiegaj przetwarzaniu żądań przy użyciu niezdefiniowanych nazw serwerów'
date: 2018-04-19 12:42:51
categories: [PL, http, nginx, best-practice]
tags: [publications]
comments: false
favorite: false
seo:
  date_modified: 2020-01-31 09:36:05 +0100
---

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
