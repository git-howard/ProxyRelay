@echo off
setlocal

set "VS_PATH=D:\Tools\Microsoft Visual Studio\18\Community"
set "VCVARSALL=%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat"

if not exist "%VCVARSALL%" (
    echo ERROR: Visual Studio not found at %VS_PATH%
    pause
    exit /b 1
)

echo ========================================
echo  ProxyRelay Build Script
echo ========================================

echo.
echo [1/4] Updating build version timestamp...
cmake -P scripts\update_version.cmake

echo.
echo [2/4] Initializing MSVC environment...
call "%VCVARSALL%" x64 >nul 2>&1

if not exist build mkdir build

if exist "build\CMakeFiles\ProxyRelay.dir\src\Version.cpp.obj" (
    del /f /q "build\CMakeFiles\ProxyRelay.dir\src\Version.cpp.obj" >nul 2>&1
)
if exist "build\CMakeFiles\ProxyRelay.dir\resources\app.rc.res" (
    del /f /q "build\CMakeFiles\ProxyRelay.dir\resources\app.rc.res" >nul 2>&1
)

echo.
echo [3/4] Configuring project...
cmake -S . -B build -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release
if errorlevel 1 (
    echo CMake configuration failed!
    pause
    exit /b 1
)

echo.
echo [4/4] Building project...
cmake --build build --config Release
if errorlevel 1 (
    echo Build failed!
    pause
    exit /b 1
)

echo.
echo ========================================
echo  Build successful!
echo  Output: build\ProxyRelay.exe
echo ========================================

taskkill /f /im ProxyRelay.exe >nul 2>&1
ping -n 2 127.0.0.1 >nul
copy /y build\ProxyRelay.exe ProxyRelay.exe >nul

echo  Copied to: ProxyRelay.exe
echo ========================================
