---
layout: post
title: 'NGINX: 10 kluczowych zasad'
date: 2019-06-22 09:17:04
categories: [PL, http, nginx, best-practices]
tags: [publications]
comments: false
favorite: false
seo:
  date_modified: 2020-01-31 09:36:05 +0100
---

Istnieje wiele rzeczy, które możesz zrobić, aby ulepszyć konfigurację serwera NGINX. W tym wpisie przedstawię 10 zasad, moim zdaniem bardzo ważnych, które bezwzględnie należy stosować podczas konfiguracji. Niektóre są pewnie oczywiste, inne może nie.

# Spis treści

- **[Zdefiniuj dyrektywy nasłuchiwania za pomocą pary adres:port](#zdefiniuj-dyrektywy-nasłuchiwania-za-pomocą-pary-adresport)**

# Zdefiniuj dyrektywy nasłuchiwania za pomocą pary adres:port

NGINX tłumaczy wszystkie niepełne dyrektywy `listen` zastępując brakujące wartości ich wartościami domyślnymi.

Co więcej, oceni dyrektywę `server_name` tylko wtedy, gdy będzie musiał rozróżnić bloki serwera pasujące do tego samego poziomu w dyrektywie `listen`.

Ustawienie pary **adres:port** zapobiega subtelnym błędom, które mogą być trudne do debugowania, np. jeżeli mamy w konfiguracji dyrektywę `listen *:80` i kilka bloków `server`, w których zdiefiniowana jest ta dyrektywa, zostanie ona uzupełniona i w wyniku będzie wyglądać tak: `listen 0.0.0.0:80`. Następnie dodając w którymś miejscu konfiguracji `listen 192.168.50.2:80` wszystkie bloki `server` zawierające pierwszą dyrektywę `listen` (uzupełnioną przez NGINX) będą miały niższy priorytet i nie będę przetwarzane (request z nagłówkiem `Host` niepasującym do `server_name` wpadnie do dyrektywy `listen` oznaczonej jako `default_server`.

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
