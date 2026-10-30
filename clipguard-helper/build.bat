@echo off
REM ---------------------------------------------------------------------------
REM Builds standalone Aegis Clip Guard (bin\aegis-clipguard.exe) using ONLY the
REM C# 5 compiler shipped inside Windows (.NET Framework 4.8). Zero downloads.
REM ---------------------------------------------------------------------------
setlocal
set FW=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319
set WM=%WINDIR%\System32\WinMetadata
set OUT=%~dp0bin

if not exist "%OUT%" mkdir "%OUT%"

"%FW%\csc.exe" /nologo /target:exe /platform:x64 /optimize+ ^
  /out:"%OUT%\aegis-clipguard.exe" ^
  /resource:"%~dp0..\shared-fixtures\bip39-english.txt",Aegis.ClipGuard.bip39-english.txt ^
  /r:"%FW%\System.Drawing.dll" ^
  /r:"%FW%\System.Windows.Forms.dll" ^
  /r:"%FW%\System.Numerics.dll" ^
  /r:"%FW%\System.IO.Compression.dll" ^
  /r:"%FW%\System.IO.Compression.FileSystem.dll" ^
  /r:"%FW%\Microsoft.VisualBasic.dll" ^
  /r:"%FW%\System.Runtime.dll" ^
  /r:"%FW%\System.Runtime.WindowsRuntime.dll" ^
  /r:"%FW%\System.Runtime.InteropServices.WindowsRuntime.dll" ^
  /r:"%WM%\Windows.Foundation.winmd" ^
  /r:"%WM%\Windows.ApplicationModel.winmd" ^
  /r:"%WM%\Windows.Media.winmd" ^
  /r:"%WM%\Windows.Globalization.winmd" ^
  /r:"%WM%\Windows.Graphics.winmd" ^
  /r:"%WM%\Windows.Storage.winmd" ^
  /recurse:"%~dp0src\*.cs"

exit /b %ERRORLEVEL%
