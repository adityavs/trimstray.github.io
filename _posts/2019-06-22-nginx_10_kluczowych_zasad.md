---
layout: post
title: NGINX: 10 kluczowych zasad
date: 2019-06-22 09:17:04
categories: [PL, http, nginx, best-practices]
tags: [publications]
comments: false
favorite: false
---

Istnieje wiele rzeczy, które możesz zrobić, aby ulepszyć konfigurację serwera NGINX. W tym wpisie przedstawię 10 zasad, moim zdaniem bardzo ważnych, które bezwzględnie należy stosować podczas konfiguracji. Niektóre są pewnie oczywiste, inne może nie.

# Spis treści

- **[Opis wybranych przekierowań](#opis-wybranych-przekierowań)**

# Zdefiniuj dyrektywy nasłuchiwania za pomocą pary adres:port

NGINX tłumaczy wszystkie niepełne dyrektywy `listen`, zastępując brakujące wartości ich wartościami domyślnymi.

Co więcej, oceni dyrektywę `server_name` tylko wtedy, gdy będzie musiał rozróżnić bloki serwera pasujące do tego samego poziomu w dyrektywie `listen`.

Ustawienie pary adres:port zapobiega subtelnym błędom, które mogą być trudne do debugowania. Ponadto brak adresu IP oznacza powiązanie ze wszystkimi adresami IP w systemie, co może powodować wiele problemów i co do zasady jest bardzo złą praktyką – zaleca się konfigurowanie tylko minimalnego dostępu do sieci dla usług.

Przykład:

```nginx
# Testowy request:
$ curl -Iks http://api.random.com

# Po stronie serwera:
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
