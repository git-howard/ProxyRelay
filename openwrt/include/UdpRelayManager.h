#pragma once

#include "Common.h"
#include "Database.h"
#include "OpenSSLSession.h"
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <memory>
#include <netinet/in.h>

class UdpRelayManager {
public:
    static UdpRelayManager& Instance();

    bool Initialize();
    void Stop();

    // 透明代理 UDP 数据包处理 (TProxy)
    void HandleTransparentUdp(SOCKET udpListenSock, const sockaddr_in& clientAddr,
                              const sockaddr_in& origDst, const char* data, size_t len);

    // SOCKS5 UDP ASSOCIATE 处理
    void HandleSocks5UdpAssociate(SOCKET clientTcpSock, const std::string& clientIP,
                                  const ProxyPort& port, int userId,
                                  const std::string& username, const char* cmdBuf,
                                  std::shared_ptr<OpenSSLSession> tlsSession);

private:
    UdpRelayManager();
    ~UdpRelayManager();

    struct UdpSession {
        std::string sessionKey;
        uint64_t connId = 0;
        std::atomic<bool> running{true};
        std::chrono::steady_clock::time_point lastActive;

        // 客户端信息
        sockaddr_in clientAddr{};
        sockaddr_in origDst{};
        bool isTransparent = true;
        SOCKET socksClientUdpSock = INVALID_SOCKET;

        // 上游/直连信息
        bool isDirect = false;
        SOCKET upstreamSock = INVALID_SOCKET;
        SOCKET tcpControlSock = INVALID_SOCKET;
        sockaddr_in upstreamRelayAddr{};

        // 透明代理源地址伪造套接字 (IP_TRANSPARENT)
        SOCKET spoofSock = INVALID_SOCKET;

        int userId = 0;
        int portId = 0;
        std::string username;
        std::string clientIP;
        std::string displayTarget;
        std::string inboundType;
        std::string proxyDesc;

        std::thread workerThread;

        ~UdpSession() {
            running.store(false);
            if (workerThread.joinable()) {
                workerThread.detach();
            }
            if (upstreamSock != INVALID_SOCKET) {
                closesocket(upstreamSock);
                upstreamSock = INVALID_SOCKET;
            }
            if (tcpControlSock != INVALID_SOCKET) {
                closesocket(tcpControlSock);
                tcpControlSock = INVALID_SOCKET;
            }
            if (spoofSock != INVALID_SOCKET) {
                closesocket(spoofSock);
                spoofSock = INVALID_SOCKET;
            }
            if (socksClientUdpSock != INVALID_SOCKET) {
                closesocket(socksClientUdpSock);
                socksClientUdpSock = INVALID_SOCKET;
            }
        }
    };

    // 建立上游 UDP 通道（支持多节点重试与自动兜底）
    bool EstablishUpstreamChannel(int preferredProxyId, const std::string& targetGroup,
                                  SOCKET& outTcpCtrl, sockaddr_in& outRelayUdpAddr,
                                  std::string& outDesc, int& outPortId, bool& outIsDirect,
                                  bool isFallback = false);

    // 建立上游 SOCKS5 UDP ASSOCIATE 握手
    SOCKET ConnectUpstreamSocks5Udp(const std::string& host, int port,
                                   const std::string& user, const std::string& pass,
                                   sockaddr_in& outRelayUdpAddr);

    // 后台会话垃圾回收
    void ScavengerThread();

    std::atomic<bool> running_{false};
    std::mutex sessionsMutex_;
    std::map<std::string, std::shared_ptr<UdpSession>> sessions_;
    std::thread scavengerThread_;
};
