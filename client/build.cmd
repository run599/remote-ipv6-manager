@echo off
REM ============================================================================
REM  build.cmd -- anti-detection build entry point (ASCII only!)
REM
REM  NOTE: this file MUST stay pure ASCII. cmd.exe parses .cmd using the OEM code
REM  page (GBK on this machine), so UTF-8 Chinese comments break parsing.
REM  Chinese documentation lives in the .py tools and in CMakeLists.txt.
REM
REM  Usage:
REM      build.cmd              full build (with packing + criteria report)
REM      build.cmd nopack       skip .r6ms encryption (for reverse-engineering)
REM      build.cmd verify       re-run packing + criteria checks only
REM
REM  Build order (do not reorder):
REM      1. preprocess literals        tools/obfuscate_strings.py --run
REM      2. cmake configure + build    (MSVC + Ninja)
REM      3. POST_BUILD steps, in order:
REM           editbin /RELEASE          clear PE Rich Header (toolchain fingerprint)
REM           tools/normalize_pe.py     clear DEBUG directory
REM           tools/pack_sections.py    encrypt the literal ciphertext section .r6ms
REM           tools/check_version.py    read back version info (fails if missing)
REM           tools/verify_compat.py   anti-detection criteria report
REM ============================================================================
setlocal enabledelayedexpansion
set "SRC=%~dp0"
set "BUILD=%SRC%build"

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo [build] vswhere not found. Run from a Developer Command Prompt instead.
  exit /b 1
)
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -property installationPath`) do set "VSPATH=%%i"
if not defined VSPATH (
  echo [build] Visual Studio not found.
  exit /b 1
)
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
  echo [build] vcvars64.bat failed.
  exit /b 1
)

if /i "%~1"=="verify" goto :verify

echo [build] step 1/3: preprocess string literals and API hashes
python "%SRC%tools\gen_hashes.py" --api-only || goto :fail
python "%SRC%tools\obfuscate_strings.py" --run || goto :fail

echo [build] step 2/3: configure and build
set "PACKOPT=-DR6M_PACK=ON"
if /i "%~1"=="nopack" set "PACKOPT=-DR6M_PACK=OFF"
cmake -S "%SRC%" -B "%BUILD%" -G Ninja -DCMAKE_BUILD_TYPE=Release %PACKOPT% || goto :fail
cmake --build "%BUILD%" --target RemoteClient || goto :fail

echo [build] done: %BUILD%\RemoteClient.exe
goto :eof

:verify
echo [build] step 3/3: packing integrity + anti-detection criteria
python "%SRC%tools\pack_sections.py" verify "%BUILD%\RemoteClient.exe"
python "%SRC%tools\check_version.py" "%BUILD%\RemoteClient.exe"
python "%SRC%tools\verify_compat.py" "%BUILD%\RemoteClient.exe"
goto :eof

:fail
echo [build] FAILED
exit /b 1
