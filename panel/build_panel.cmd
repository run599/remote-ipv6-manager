@echo off
REM ============================================================================
REM  build_panel.cmd -- operator panel (Qt6) hardened build + self-contained deploy
REM  ASCII only! cmd.exe parses .cmd with the OEM code page (GBK), so UTF-8
REM  Chinese comments break parsing. Chinese docs live in the sources.
REM
REM  Usage:
REM      build_panel.cmd            build + deploy to panel\dist
REM      build_panel.cmd verify     only run the anti-detection checks on dist
REM
REM  Why the ASCII mirror: Qt's moc.exe cannot create its output directory when
REM  the project path contains non-ASCII characters -- it fails with
REM      moc: Cannot create ... Error: No such file or directory
REM  even though the directory exists. This repo's path contains Chinese, so the
REM  sources are mirrored to an ASCII scratch dir before configuring.
REM
REM  Why windeployqt is mandatory (not optional):
REM      The panel links Qt dynamically. Launching it from a shell whose PATH has
REM      no Qt bin directory makes it die instantly with a missing-DLL error --
REM      the exact "crashed, cannot find the Qt component" symptom. windeployqt
REM      copies Qt6*.dll + the MinGW runtime + the platform/QML plugins next to
REM      the exe, so panel\dist runs on any machine without Qt installed.
REM ============================================================================
setlocal
set "SRC=%~dp0"
REM Strip the trailing backslash from %~dp0: with it, cmd expands "%SRC%" to
REM "...\panel\" and the final backslash escapes the closing quote, so tools
REM like "cmake -E copy_directory" receive a mangled argument and print usage.
REM CMake 4.x no longer tolerates that (older versions did), which is why this
REM build used to pass and later started failing at step 1/5.
if "%SRC:~-1%"=="\" set "SRC=%SRC:~0,-1%"
if not defined QT_PREFIX set "QT_PREFIX=D:/qtr/6.11.1/mingw_64"
if not defined MINGW_BIN set "MINGW_BIN=D:/qtr/Tools/mingw1310_64/bin"
set "ASCII_ROOT=%TEMP%\r6m_panel_build"
set "BUILD=%ASCII_ROOT%\build"
REM SRC no longer carries a trailing backslash (see above) -- joins must add it.
set "DIST=%SRC%\dist"

if /i "%~1"=="verify" goto :verify

echo [panel] 1/5 mirror sources to an ASCII path
if exist "%ASCII_ROOT%" cmake -E remove_directory "%ASCII_ROOT%"
cmake -E copy_directory "%SRC%" "%ASCII_ROOT%" || goto :fail
if exist "%ASCII_ROOT%\build" cmake -E remove_directory "%ASCII_ROOT%\build"

echo [panel] 2/5 configure (Qt=%QT_PREFIX%)
set "PATH=%QT_PREFIX%\bin;%MINGW_BIN%;%PATH%"
cmake -S "%ASCII_ROOT%" -B "%BUILD%" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="%QT_PREFIX%" || goto :fail

echo [panel] 3/5 build
cmake --build "%BUILD%" || goto :fail

echo [panel] 4/5 windeployqt (bundle Qt runtime so dist is self-contained)
"%QT_PREFIX%\bin\windeployqt.exe" --release --no-translations --qmldir "%ASCII_ROOT%\qml" "%BUILD%\RMMPanel.exe" || goto :fail

echo [panel] 5/5 assemble dist (runtime only -- no build-system files)
if exist "%DIST%" cmake -E remove_directory "%DIST%"
cmake -E make_directory "%DIST%"
cmake -E copy "%BUILD%\RMMPanel.exe" "%DIST%\RMMPanel.exe" || goto :fail
for %%F in ("%BUILD%\*.dll") do cmake -E copy "%%~fF" "%DIST%\%%~nxF"
for %%D in (platforms qml tls imageformats iconengines networkinformation generic) do (
  if exist "%BUILD%\%%D" cmake -E copy_directory "%BUILD%\%%D" "%DIST%\%%D"
)

echo [panel] done: %DIST%\RMMPanel.exe
echo [panel] NOTE: dist is self-contained; no Qt install and no PATH changes needed.
goto :verify

:verify
echo [panel] anti-detection checks on dist
python "%SRC%\tools\verify_panel_obf.py" "%DIST%\RMMPanel.exe"
goto :eof

:fail
echo [panel] FAILED
exit /b 1
