cmake_minimum_required(VERSION 3.15)
project(ProxyRelay VERSION 1.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Windows specific settings
if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0601)
    add_definitions(-DNOMINMAX)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SUBSYSTEM:WINDOWS")
    set(CMAKE_RC_FLAGS "${CMAKE_RC_FLAGS} /c 65001")
endif()

# Source files
set(SOURCES
    src/main.cpp
    src/ProxyServer.cpp
    src/Database.cpp
    src/UserManager.cpp
    src/TrafficMonitor.cpp
    src/ConnectionLogger.cpp
    src/XrayManager.cpp
    src/ClashManager.cpp
    src/MainWindow.cpp
    src/Utils.cpp
    src/Rules.cpp
    src/Version.cpp
    src/ServiceManager.cpp
    src/RealtimeConnectionManager.cpp
    src/SchannelSession.cpp
    src/WebUIManager.cpp
    src/SharedStatusManager.cpp
    libs/sqlite3.c
)

# 强制每次构建时重新生成 BuildVersion.h 并重新编译 Version.cpp 和 app.rc 以更新编译时间戳与二进制版本
add_custom_target(UpdateBuildTimestamp ALL
    COMMAND ${CMAKE_COMMAND} -P "${CMAKE_SOURCE_DIR}/scripts/update_version.cmake"
    COMMAND ${CMAKE_COMMAND} -E rm -f "${CMAKE_BINARY_DIR}/CMakeFiles/ProxyRelay.dir/src/Version.cpp.obj"
    COMMAND ${CMAKE_COMMAND} -E rm -f "${CMAKE_BINARY_DIR}/CMakeFiles/ProxyRelay.dir/resources/app.rc.res"
    COMMAND ${CMAKE_COMMAND} -E touch "${CMAKE_SOURCE_DIR}/src/Version.cpp"
    COMMENT "Ensuring BuildVersion.h, Version.cpp, and app.rc recompile with fresh timestamp..."
)

set(HEADERS
    include/ProxyServer.h
    include/Database.h
    include/UserManager.h
    include/TrafficMonitor.h
    include/ConnectionLogger.h
    include/XrayManager.h
    include/ClashManager.h
    include/MainWindow.h
    include/Utils.h
    include/Rules.h
    include/ServiceManager.h
    include/RealtimeConnectionManager.h
    include/SchannelSession.h
    include/WebUIManager.h
    include/SharedStatusManager.h
    libs/sqlite3.h
)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/libs)
include_directories(${CMAKE_SOURCE_DIR}/libs/webview2/build/native/include)

# Create executable
add_executable(${PROJECT_NAME} WIN32 ${SOURCES} ${HEADERS} resources/app.rc)

# 确保在编译前先更新时间戳
add_dependencies(${PROJECT_NAME} UpdateBuildTimestamp)

# Link libraries
target_link_libraries(${PROJECT_NAME} 
    ws2_32
    comctl32
    gdi32
    gdiplus
    msimg32
    uxtheme
    dwmapi
    wininet
    secur32
    crypt32
    ncrypt
    bcrypt
    advapi32
    comdlg32
    shlwapi
    version
    ${CMAKE_SOURCE_DIR}/libs/webview2/build/native/x64/WebView2LoaderStatic.lib
)

# Enable Unicode
target_compile_definitions(${PROJECT_NAME} PRIVATE UNICODE _UNICODE)

# MSVC UTF-8 support for Chinese characters
if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /utf-8)
endif()
