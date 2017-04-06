# sdig
Async DNS resolver example with Scala and Netty 4

## Build
```sh
$ sbt assembly
```

## Run
```sh
$ sbt "run --help"
```

## Query
```sh
$ sbt "run www.google.com -t aaaa"

;; ->>HEADER<<- opcode: QUERY(0), status: NoError(0), id: 7687
;; flags: qr rd ra; QUERY: 1, ANSWSER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;; www.google.com.	IN	AAAA

;; ANSWER SECTION:
www.google.com.                 	131	IN	AAAA	2404:6800:4005:801:0:0:0:2004

;; Query time: 342 msec
;; SERVER: 8.8.8.8#53
;; WHEN: Thu, 6 Apr 2017 14:05:02 +0800
[success] Total time: 2 s, completed 2017-4-6 14:05:02
```
