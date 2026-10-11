@echo off
rem AikawaMei CLI, pinned to the tor target.
rem AIKAWAMEI_TARGET only sets a default; an explicit --target still wins.
setlocal
set "AIKAWAMEI_TARGET=tor"
node "%~dp0..\cli\index.mjs" %*
exit /b %ERRORLEVEL%