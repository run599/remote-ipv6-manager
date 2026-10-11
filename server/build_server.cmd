@echo off
REM ============================================================================
REM  build_server.cmd -- RMM server hardened build (ASCII only!)
REM
REM  This file MUST stay pure ASCII: cmd.exe parses .cmd with the OEM code page
REM  (GBK here), so UTF-8 Chinese comments break parsing. Chinese docs live in
REM  the Go/Python sources and in CMakeLists.txt.
REM
REM  Build order (do not reorder):
REM      1. tools/gen_obf_strings.py   regenerate the cipher tables for BOTH
REM                                    server (Go) and panel (C++); they share
REM                                    the same keystream so literals map 1:1
REM      2. go build -trimpath -ldflags "-s -w"
REM      3. tools/verify_server_obf.py static checks
REM      4. optional: --live <url>     dynamic HTTP fingerprint check
REM
REM  Why -trimpath matters: without it the Go binary embeds absolute source
REM  paths including the build user name (measured leak in this repo's path).
REM ============================================================================
setlocal
set "SRC=%~dp0"

if /i "%~1"=="verify" goto :verify

echo [build] step 1/3: generate obfuscation tables
python "%SRC%tools\gen_obf_strings.py" || goto :fail

echo [build] step 2/3: build hardened server binary
set "PATH=D:\DevTools\go\bin;%PATH%"
pushd "%SRC%"
go build -trimpath -ldflags "-s -w" -o server-obf.exe . || (popd & goto :fail)
popd

echo [build] done: %SRC%server-obf.exe
echo [build] step 3/3: static anti-detection checks
python "%SRC%tools\verify_server_obf.py" "%SRC%server-obf.exe"
goto :eof

:verify
python "%SRC%tools\verify_server_obf.py" "%SRC%server-obf.exe" %2 %3 %4
goto :eof

:fail
echo [build] FAILED
exit /b 1
