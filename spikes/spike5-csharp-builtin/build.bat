@echo off
REM ---------------------------------------------------------------------------
REM Aegis spike 5 build: uses ONLY the C# compiler built into Windows.
REM No downloads, no installs. Output: Spike5.exe in this folder.
REM ---------------------------------------------------------------------------
setlocal
set FW=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319
set WM=%WINDIR%\System32\WinMetadata

"%FW%\csc.exe" /nologo /target:exe /platform:x64 /optimize+ /out:"%~dp0Spike5.exe" ^
  /r:"%FW%\System.Runtime.dll" ^
  /r:"%FW%\System.Runtime.WindowsRuntime.dll" ^
  /r:"%FW%\System.Runtime.InteropServices.WindowsRuntime.dll" ^
  /r:"%WM%\Windows.Foundation.winmd" ^
  /r:"%WM%\Windows.ApplicationModel.winmd" ^
  /r:"%WM%\Windows.Media.winmd" ^
  /r:"%WM%\Windows.Globalization.winmd" ^
  "%~dp0Spike5.cs"
exit /b %ERRORLEVEL%

