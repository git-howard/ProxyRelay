@echo off
chcp 65001 >nul
echo ========================================
echo  ProxyRelay 构建脚本
echo ========================================

:: 检查是否存在 build 目录
if not exist build mkdir build
cd build

:: 运行 CMake
echo.
echo [1/2] 正在配置项目...
cmake .. -G "Visual Studio 17 2022" -A x64
if errorlevel 1 (
    echo CMake 配置失败！
    pause
    exit /b 1
)

:: 编译
echo.
echo [2/2] 正在编译项目...
cmake --build . --config Release
if errorlevel 1 (
    echo 编译失败！
    pause
    exit /b 1
)

echo.
echo ========================================
echo  编译成功！
echo  输出文件: build\Release\ProxyRelay.exe
echo ========================================

:: 复制到根目录
copy Release\ProxyRelay.exe ..\ProxyRelay.exe >nul

echo  已复制到: ProxyRelay.exe
echo ========================================
pause
