@echo off
REM ---------------------------------------------------------------------------
REM build.bat - One-click reproducible build for Aegis Wallet Shield
REM Builds Browser Guard + Clip Guard, runs verification checks, and outputs
REM release zips + SHA256SUMS.txt into dist\.
REM ---------------------------------------------------------------------------
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\build.ps1" %*
exit /b %ERRORLEVEL%

