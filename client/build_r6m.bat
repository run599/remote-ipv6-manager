@echo off
REM r6m client build wrapper (ASCII only) - generated 2026-10-16
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (echo [build] vcvars failed & exit /b 1)
set "CM=D:\DevTools\cmake\bin\cmake.exe"
set "SRC=%~dp0"
set "SRC=%SRC:~0,-1%"
echo [build] configure
"%CM%" -S "%SRC%" -B "%SRC%\build" -G Ninja -DCMAKE_BUILD_TYPE=Release -DR6M_PACK=OFF
if errorlevel 1 (echo [build] configure FAILED & exit /b 1)
echo [build] compile
"%CM%" --build "%SRC%\build" --target RemoteClient
if errorlevel 1 (echo [build] compile FAILED & exit /b 1)
echo [build] OK: %SRC%\build\RemoteClient.exe
endlocal
