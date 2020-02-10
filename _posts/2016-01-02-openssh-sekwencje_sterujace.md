---
layout: post
title: OpenSSH - sekwencje sterujące
date: 2016-01-02 23:01:38
categories: [PL, system, openssh]
tags: [publications]
comments: false
favorite: false
seo:
  date_modified: 2020-01-31 09:36:05 +0100
---

Klient SSH udostępnia **dodatkowe sekwencje sterujące** za pomocą których można wykonywać przydatne akcje. Normalne znaki przekazywane są przez zestawioną sesję SSH więc żadne z nich nie będą działać w przypadku wykonania specjalnych czynności.

W celu wyświetlenia dodatkowych kombinacji klawiszy należy nacisnąć (z poziomu nawiązanej sesji) klawisze `~` oraz `?` (jeden po drugim).

Oto niektóre z dostępnych opcji:

- `~.` - kończy wszystkie nawiązane sesje/połączenia
- `~B` - wysyła sygnał _BREAK_ do zdalnego systemu
- `~C` - otwiera prosty interpreter (`ssh>`)
- `~V/v` - przechodzi między poziomem widoczności komunikatów lub inaczej mówiąc zwiększa/zmniejsza ich poziom widoczności (verbose mode)
- `~^Z` - wstrzymuje (zawiesza) klienta ssh
- `~#` - wyświetla nawiązane połączenia
- `~&` - kończy sesję (przydatne jeżeli wykonujemy reboot systemu i chcemy natychmiast zakończyć sesję podczas restartu)

I tak jeżeli zdarzy się, że konsola się zawiesi np. przez problemy z siecią, wykonuję kombinację `~` + `.` aby zakończyć sesję i wrócić do początkowej konsoli, z której się połączyłem.
