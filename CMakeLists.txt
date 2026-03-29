cmake_minimum_required(VERSION 3.15)
project(ProxyRelay VERSION 1.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Windows specific settings
if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0601)
    add_definitions(-DNOMINMAX)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SUBSYSTEM:WINDOWS")
endif()

# Source files
set(SOURCES
    src/main.cpp
    src/ProxyServer.cpp
    src/Database.cpp
    src/UserManager.cpp
    src/TrafficMonitor.cpp
    src/ConnectionLogger.cpp
    src/MainWindow.cpp
    src/Dialogs.cpp
    src/Utils.cpp
    src/Rules.cpp
    src/Version.cpp
    libs/sqlite3.c
)

# 强制每次构建时重新编译 Version.cpp 以更新编译时间戳
# 创建一个自定义目标，在每次构建前更新 Version.cpp 的时间戳
add_custom_target(UpdateBuildTimestamp ALL
    COMMAND ${CMAKE_COMMAND} -E touch "${CMAKE_SOURCE_DIR}/src/Version.cpp"
    COMMENT "Updating build timestamp..."
)

set(HEADERS
    include/ProxyServer.h
    include/Database.h
    include/UserManager.h
    include/TrafficMonitor.h
    include/ConnectionLogger.h
    include/MainWindow.h
    include/Utils.h
    include/Rules.h
    libs/sqlite3.h
)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/libs)

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
)

# Enable Unicode
target_compile_definitions(${PROJECT_NAME} PRIVATE UNICODE _UNICODE)

# MSVC UTF-8 support for Chinese characters
if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /utf-8)
endif()
