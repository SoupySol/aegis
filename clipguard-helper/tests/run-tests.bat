@echo off
REM ---------------------------------------------------------------------------
REM Verifies standalone Aegis Clip Guard with zero external downloads:
REM   1. check-no-network.ps1 static source audit
REM   2. build.bat -> bin\aegis-clipguard.exe
REM   3. Ed25519Tests.exe (301 shared vectors)
REM   4. ClipGuardTests.exe (227 corpus cases, Notepad, Sticky Notes, FileSweep,
REM      DisplayPath redaction, FileActions, standalone CLI & headless STA UI)
REM   5. QaStressTests.exe (50k/45k window seams, 2,337-char JSON seam, multi-seed
REM      dedup, corrupt Office/image files, NTFS single+twin junction loops,
REM      TOCTOU reparse guard, zero-browser/zero-registry static audit)
REM ---------------------------------------------------------------------------
setlocal
set FW=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319
set OUT=%~dp0bin
if not exist "%OUT%" mkdir "%OUT%"

echo === [1/5] Checking zero-network constraint ===
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\tools\check-no-network.ps1"
if errorlevel 1 exit /b 1

echo === [2/5] Building bin\aegis-clipguard.exe ===
call "%~dp0..\build.bat"
if errorlevel 1 exit /b 1

echo === [3/5] Running Ed25519Tests ===
"%FW%\csc.exe" /nologo /target:exe /platform:x64 /optimize+ /out:"%OUT%\Ed25519Tests.exe" ^
  /r:System.Numerics.dll ^
  "%~dp0Ed25519Tests.cs" "%~dp0..\src\Crypto\Ed25519PublicKey.cs"
if errorlevel 1 exit /b 1

"%OUT%\Ed25519Tests.exe" "%~dp0..\..\shared-fixtures\ed25519-vectors.txt"
if errorlevel 1 exit /b 1

echo === [4/5] Building and running ClipGuardTests ===
copy /y "%~dp0..\bin\aegis-clipguard.exe" "%OUT%\aegis-clipguard.exe" >nul
if errorlevel 1 exit /b 1

"%FW%\csc.exe" /nologo /target:exe /platform:x64 /optimize+ /out:"%OUT%\ClipGuardTests.exe" ^
  /r:"%FW%\System.Drawing.dll" ^
  /r:"%FW%\System.Windows.Forms.dll" ^
  /r:"%FW%\System.Web.Extensions.dll" ^
  /r:"%FW%\System.IO.Compression.dll" ^
  /r:"%FW%\System.IO.Compression.FileSystem.dll" ^
  /r:"%OUT%\aegis-clipguard.exe" ^
  "%~dp0ClipGuardTests.cs"
if errorlevel 1 exit /b 1

"%OUT%\ClipGuardTests.exe" "%~dp0..\..\shared-fixtures\detector-corpus.jsonl" "%~dp0..\bin\aegis-clipguard.exe"
if errorlevel 1 exit /b 1

echo === [5/5] Building and running QaStressTests ===
"%FW%\csc.exe" /nologo /target:exe /platform:x64 /optimize+ /out:"%OUT%\QaStressTests.exe" ^
  /r:"%FW%\System.Drawing.dll" ^
  /r:"%FW%\System.Windows.Forms.dll" ^
  /r:"%FW%\System.IO.Compression.dll" ^
  /r:"%FW%\System.IO.Compression.FileSystem.dll" ^
  /r:"%OUT%\aegis-clipguard.exe" ^
  "%~dp0QaStressTests.cs"
if errorlevel 1 exit /b 1

"%OUT%\QaStressTests.exe" "%~dp0.." "%~dp0..\bin\aegis-clipguard.exe"
exit /b %ERRORLEVEL%
