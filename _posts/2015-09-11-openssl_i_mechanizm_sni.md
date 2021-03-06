---
layout: post
title: OpenSSL i mechanizm SNI
date: 2015-09-11 07:51:13
categories: [PL, security, openssl]
tags: [publications]
comments: false
favorite: false
seo:
  date_modified: 2020-02-11 09:19:12 +0100
---

Często zdarza mi się testować połączenia do aplikacji chronionych protokołem SSL/TLS. Za pomocą biblioteki `openssl` możemy testować **każdą** usługę działającą na tych protokołach. Po nawiązaniu połączenia można nim sterować stosując komendy/wiadomości dla każdego protokołu warstwy aplikacji.

# Czym jest rozszerzenie SNI?

**SNI** (ang. _Server Name Indication_) jest rozszerzeniem protokołu TLS, które umożliwia serwerom używanie wielu certyfikatów na jednym adresie IP.

Ponieważ liczba dostępnych adresów IP stale maleje, pozostałe mogą być alokowane bardziej efektywnie. W większości przypadków można uruchomić witrynę z obsługą protokołu SSL bez konieczności zakupu określonego adresu IP.

Rozszerzenie to pozwala klientowi na wskazanie nazwy hosta, z którym klient stara się nawiązać połączenie na początku procesu uzgadniania. Jak zostało powiedziane wyżej - pozwala to serwerowi na przedstawienie wielu certyfikatów na tym samym adresie IP i numerze portu, a tym samym umożliwia korzystanie z tego samego adresu IP przez wiele bezpiecznych witryn (https) a także innych usług za pośrednictwem protokołu TLS bez konieczności korzystania dla tych usług z tego samego certyfikatu.

  > Żądana nazwa hosta (domeny), którą ustala klient podczas połączenia nie jest szyfrowana, dzięki czemu podsłuchując można zobaczyć z którą witryną nawiązywane będzie połączenie.

## Proces nawiązywania połączenia

Podczas nawiązywania połączenia TLS klient wysyła żądanie z prośbą o certyfikat z serwera. Gdy serwer wysyła certyfikat, klient sprawdza go i porównuje nazwę z nazwami zawartymi w certyfikacie (pola **CN** oraz **SAN**).

Jeżeli domena zostanie znaleziona połączenie odbywa się w normalny sposób (standardowa sesja SSL/TLS). Jeżeli domena nie zostanie znaleziona oprogramowanie klienta powinno wyświetlić ostrzeżenie zaś połączenie powinno zostać przerwane.

  > Niedopasowanie nazw może oznaczać próbę ataku typu **MITM**. Niektóre z aplikacji (np. przeglądarki internetowe) pozwalają na ominięcie ostrzeżenia w celu kontynuowania połączenia - przerzucają tym samym odpowiedzialność na użytkownika, który często jest nieświadomy czyhających zagrożeń.

## Szczegóły połączenia

Gdy klient (np. przeglądarka) składa wniosek o witrynę ustawia specjalny nagłówek HTTP (nagłówek `Host`), określający do której witryny klient próbuje uzyskać dostęp.

Serwer odpowiada klientowi dopasowując podaną zawartość nagłówka do domeny i wyświetla odpowiednią zawartość. Podanej techniki nie można zastosować do protokołu HTTPS ponieważ nagłówek ten jest wysyłany dopiero po zakończeniu uzgadniania sesji TLS.

Tym samym powstaje następujący problem:

- serwer potrzebuje nagłówków HTTP w celu określenia, która witryna (domena) powinna być dostarczona do klienta
- nie może jednak uzyskać tych nagłówków bez wcześniejszego uzgodnienia sesji TLS, ponieważ wcześniej wymagane jest dostarczenie samych certyfikatów

Dlatego do tej pory (przed wprowadzeniem protokołu SNI) jedynym sposobem dostarczania różnych certyfikatów było hostowanie jednej domeny na jednym adresie IP.

Na podstawie adresu IP (dla którego doszło żądanie o zaserwowanie treści) oraz przypisanej do niego domeny serwer wybierał odpowiedni certyfikat. Pierwszym rozwiązaniem tego problemu w przypadku ruchu HTTPS jest przejście na protokół IPv6.

Rozwiązaniem tymczasowym jest właśnie wykorzystanie mechanizmu **SNI**, który wstawia żądaną nazwę hosta (domeny, adresu internetowego) w ramach uzgadniania ruchu TLS - przeglądarka wysyła tą nazwę w komunikacie `Client Hello` pozwalając serwerowi określenie najbardziej odpowiedniego certyfikatu.

Dzięki rozszerzeniu **SNI** serwer może bezpiecznie 'trzymać' wiele certyfikatów używając pojedynczego adresu IP.

## SNI a Subject Alternative Name (SAN)

Domyślnie serwer odpowiedzialny za wiele nazw hostów powinien przedstawiać inny certyfikat dla każdej domeny.

Jest to jednak niepraktyczne i niezadowalające a także zwiększa złożoność oraz koszty samego hostingu, np. przydzielenie osobnego adresu IP dla każdej witryny zwiększa koszty hostingu, ponieważ żądania adresów IP muszą być uzasadnione regionalnym rejestrem internetowym, a adresy IPv4 są już wyczerpane.

Wykorzystanie rozszerzenia SAN do przechowywania wielu domen w jednym certyfikacie rozwiązuje te problemy.

## SNI a klient

Poprawne działanie rozszerzenia **SNI** zależy od:

- poprawnej obsługi po stronie serwera (w większości przypadków każdy serwer obsługuje ten mechanizm poprawnie)
- poprawnej obsługi po stronie klienta (w większości oprogramowania funkcja ta jest zaimplementowana)

# Testowanie połączenia

## OpenSSL

Połączenie do zdalnej usługi z ustaloną nazwą domeny (rozszerzenie SNI):

```bash
echo | openssl s_client -showcerts -servername www.example.com -connect example.com:443
```

Jeżeli chcemy połączyć się bez włączonego **SNI**:

```bash
echo | openssl s_client -showcerts -connect example.com:443
```

## gnutls-cli

Wykorzystujemy rozszerzenie **SNI** (domyślnie):

```bash
gnutls-cli -p 443 www.example.com
```

Bez wykorzystania rozszerzenia **SNI**:

```bash
gnutls-cli --disable-sni -p 443 www.example.com
```
