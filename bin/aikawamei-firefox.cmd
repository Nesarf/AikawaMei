@echo off
rem AikawaMei CLI, pinned to the firefox target.
rem AIKAWAMEI_TARGET only sets a default; an explicit --target still wins.
setlocal
set "AIKAWAMEI_TARGET=firefox"
node "%~dp0..\cli\index.mjs" %*
exit /b %ERRORLEVEL%