cmake_minimum_required(VERSION 3.13)
project(proxyrelay VERSION 1.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# 编译优化与安全选项，适应嵌入式环境
add_compile_options(-Wall -Wextra -Wno-unused-parameter -O2 -pthread)

# 寻找 OpenSSL 和 线程库
set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# 包含路径
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/libs
    ${OPENSSL_INCLUDE_DIR}
)

# 源码列表
set(SOURCES
    src/main.cpp
    src/Utils.cpp
    src/Database.cpp
    src/Rules.cpp
    src/UserManager.cpp
    src/TrafficMonitor.cpp
    src/ConnectionLogger.cpp
    src/RealtimeConnectionManager.cpp
    src/OpenSSLSession.cpp
    src/ProxyServer.cpp
    src/TProxyServer.cpp
    src/UdpRelayManager.cpp
    src/ClashManager.cpp
    src/WebServer.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/sqlite3.c
)

# 生成二进制
add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME} PRIVATE
    Threads::Threads
    OpenSSL::SSL
    OpenSSL::Crypto
    z
    zstd
    jitterentropy
    ${CMAKE_DL_LIBS}
)
target_link_options(${PROJECT_NAME} PRIVATE -static)

# 安装规则 (用于 make install 与 OpenWrt ipk 打包)
install(TARGETS ${PROJECT_NAME} DESTINATION bin)
install(DIRECTORY files/etc/ DESTINATION /etc/ COMPONENT config)
install(DIRECTORY files/usr/ DESTINATION /usr/ COMPONENT share)
install(DIRECTORY ui/ DESTINATION /usr/share/proxyrelay/ui COMPONENT webui)
