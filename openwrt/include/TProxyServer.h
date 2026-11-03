#pragma once

#include "Common.h"
#include <atomic>
#include <thread>
#include <string>

#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif

#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT 19
#endif

#ifndef IP_RECVORIGDSTADDR
#define IP_RECVORIGDSTADDR 20
#endif

class TProxyServer {
public:
    static TProxyServer& Instance();

    bool Start(int port = 12345);
    void Stop();
    bool IsRunning() const { return running_.load(); }
    int GetPort() const { return port_.load(); }

private:
    TProxyServer() = default;
    ~TProxyServer();

    void TcpListenerThread(int port);
    void UdpListenerThread(int port);

    void HandleTcpClient(SOCKET clientSocket, const std::string& clientIP,
                         const std::string& origDstIP, int origDstPort);

    std::atomic<bool> running_{false};
    std::atomic<int> port_{0};
    std::thread tcpThread_;
    std::thread udpThread_;
    SOCKET tcpListenSock_ = INVALID_SOCKET;
    SOCKET udpListenSock_ = INVALID_SOCKET;
};
