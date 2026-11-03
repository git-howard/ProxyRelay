#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <iostream>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>

#ifndef SOCKET
using SOCKET = int;
#endif

#ifndef INVALID_SOCKET
constexpr SOCKET INVALID_SOCKET = -1;
#endif

#ifndef SOCKET_ERROR
constexpr int SOCKET_ERROR = -1;
#endif

inline int closesocket(SOCKET s) {
    return close(s);
}

// 目标地址结构
struct TargetEndpoint {
    std::string host;
    int port = 0;
    bool isIP = false;
};
