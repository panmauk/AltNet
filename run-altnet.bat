@echo off
REM AltNet launcher -- single-PC mode.
REM
REM   peer       127.0.0.1:9000    peer-to-peer transport
REM   relay      127.0.0.1:9100    relay listener
REM   gateway    127.0.0.1:8080    browser entry point (http://...)
REM   dns        127.0.0.1:15353   resolves .alt (point system DNS here later)
REM   registrar  127.0.0.1:9090    the AltNet app talks to this
REM   metrics    127.0.0.1:9999    GET /metrics shows node state
REM
REM We use port 8080 instead of 80 so this works without admin rights.
REM When you later switch the system DNS to point at us, browsers expect
REM port 80; either change the gateway port to 80 (needs admin) or use
REM a hosts-file workaround.

setlocal
set /p TOKEN=<data\registrar-token.txt

altnet.exe ^
  -listen 127.0.0.1:9000 ^
  -relay-listen 127.0.0.1:9100 ^
  -public ^
  -gateway 127.0.0.1:8080 ^
  -dns 127.0.0.1:15353 ^
  -registrar 127.0.0.1:9090 ^
  -registrar-token %TOKEN% ^
  -metrics 127.0.0.1:9999 ^
  -data data\store ^
  -keydir data\keys
