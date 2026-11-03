#include "TProxyServer.h"
#include "ProxyServer.h"
#include "UserManager.h"
#include "Rules.h"
#include "ConnectionLogger.h"
#include "RealtimeConnectionManager.h"
#include "TrafficMonitor.h"
#include "UdpRelayManager.h"
#include "Utils.h"
#include <iostream>
#include <cstring>
#include <linux/netfilter_ipv4.h>
#include <poll.h>
#include <cctype>
#include <algorithm>

namespace {

// 从 TLS ClientHello 扩展中解析提取 SNI 域名 (RFC 6066)
std::string SniffSNI(const char* data, size_t len) {
    if (len < 5) return "";
    const auto* p = reinterpret_cast<const uint8_t*>(data);
    if (p[0] != 0x16) return ""; // 必须是 TLS Handshake
    if (p[1] != 0x03) return ""; // SSL 3.0 / TLS 1.x

    size_t offset = 5;
    if (offset + 4 > len) return "";
    if (p[offset] != 0x01) return ""; // Handshake Type: ClientHello
    offset += 4; // 跳过 Handshake Type(1) 与 Length(3)

    // 跳过 Client Version(2) + Random(32)
    if (offset + 34 > len) return "";
    offset += 34;

    // Session ID
    if (offset + 1 > len) return "";
    uint8_t sessionIDLen = p[offset++];
    if (offset + sessionIDLen > len) return "";
    offset += sessionIDLen;

    // Cipher Suites
    if (offset + 2 > len) return "";
    uint16_t cipherSuitesLen = (static_cast<uint16_t>(p[offset]) << 8) | p[offset + 1];
    offset += 2;
    if (offset + cipherSuitesLen > len) return "";
    offset += cipherSuitesLen;

    // Compression Methods
    if (offset + 1 > len) return "";
    uint8_t compMethodsLen = p[offset++];
    if (offset + compMethodsLen > len) return "";
    offset += compMethodsLen;

    // Extensions
    if (offset + 2 > len) return "";
    uint16_t extensionsLen = (static_cast<uint16_t>(p[offset]) << 8) | p[offset + 1];
    offset += 2;
    size_t extEnd = std::min(len, offset + extensionsLen);

    while (offset + 4 <= extEnd) {
        uint16_t extType = (static_cast<uint16_t>(p[offset]) << 8) | p[offset + 1];
        uint16_t extLen = (static_cast<uint16_t>(p[offset + 2]) << 8) | p[offset + 3];
        offset += 4;

        if (offset + extLen > extEnd) break;

        // 0x0000 = server_name (SNI)
        if (extType == 0x0000) {
            if (extLen < 2) break;
            size_t sniOffset = offset;
            uint16_t serverNameListLen = (static_cast<uint16_t>(p[sniOffset]) << 8) | p[sniOffset + 1];
            sniOffset += 2;
            if (sniOffset + serverNameListLen > offset + extLen) break;

            while (sniOffset + 3 <= offset + extLen) {
                uint8_t nameType = p[sniOffset++];
                uint16_t nameLen = (static_cast<uint16_t>(p[sniOffset]) << 8) | p[sniOffset + 1];
                sniOffset += 2;

                if (sniOffset + nameLen > offset + extLen) break;

                if (nameType == 0) { // host_name
                    std::string sni(reinterpret_cast<const char*>(p + sniOffset), nameLen);
                    bool valid = !sni.empty();
                    for (char c : sni) {
                        if (!isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '-' && c != '_') {
                            valid = false;
                            break;
                        }
                    }
                    if (valid) return sni;
                }
                sniOffset += nameLen;
            }
            break;
        }
        offset += extLen;
    }
    return "";
}

// 从 HTTP 请求头中解析 Host 域名
std::string SniffHTTPHost(const char* data, size_t len) {
    if (len < 10) return "";
    std::string s(data, std::min(len, static_cast<size_t>(1024)));
    if (s.rfind("GET ", 0) != 0 && s.rfind("POST ", 0) != 0 &&
        s.rfind("HEAD ", 0) != 0 && s.rfind("OPTIONS ", 0) != 0 &&
        s.rfind("PUT ", 0) != 0 && s.rfind("DELETE ", 0) != 0 &&
        s.rfind("CONNECT ", 0) != 0) {
        return "";
    }

    std::string lower = Utils::ToLower(s);
    size_t pos = lower.find("\nhost:");
    if (pos == std::string::npos) return "";

    pos += 6;
    while (pos < s.length() && (s[pos] == ' ' || s[pos] == '\t')) pos++;

    size_t endPos = s.find_first_of(":\r\n", pos);
    if (endPos == std::string::npos) endPos = s.length();

    std::string host = Utils::Trim(s.substr(pos, endPos - pos));
    for (char c : host) {
        if (!isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '-' && c != '_') {
            return "";
        }
    }
    return host;
}

// 综合探测域名
std::string SniffDomain(const char* data, size_t len) {
    if (len >= 5 && static_cast<uint8_t>(data[0]) == 0x16) {
        std::string sni = SniffSNI(data, len);
        if (!sni.empty()) return sni;
    }
    return SniffHTTPHost(data, len);
}

} // namespace

TProxyServer& TProxyServer::Instance() {
    static TProxyServer instance;
    return instance;
}

TProxyServer::~TProxyServer() {
    Stop();
}

bool TProxyServer::Start(int port) {
    if (running_.load()) return true;
    port_.store(port);
    running_.store(true);

    tcpThread_ = std::thread(&TProxyServer::TcpListenerThread, this, port);
    udpThread_ = std::thread(&TProxyServer::UdpListenerThread, this, port);

    std::cout << "[TProxy] Transparent proxy gateway listening on port " << port << " (TCP/UDP)" << std::endl;
    return true;
}

void TProxyServer::Stop() {
    if (!running_.load()) return;
    running_.store(false);
    port_.store(0);

    if (tcpListenSock_ != INVALID_SOCKET) {
        shutdown(tcpListenSock_, SHUT_RDWR);
        closesocket(tcpListenSock_);
        tcpListenSock_ = INVALID_SOCKET;
    }

    if (udpListenSock_ != INVALID_SOCKET) {
        shutdown(udpListenSock_, SHUT_RDWR);
        closesocket(udpListenSock_);
        udpListenSock_ = INVALID_SOCKET;
    }

    if (tcpThread_.joinable()) tcpThread_.join();
    if (udpThread_.joinable()) udpThread_.join();
}

void TProxyServer::TcpListenerThread(int port) {
#ifdef SOCK_CLOEXEC
    tcpListenSock_ = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
#else
    tcpListenSock_ = socket(AF_INET, SOCK_STREAM, 0);
#endif
    if (tcpListenSock_ == INVALID_SOCKET) return;

    int opt = 1;
    setsockopt(tcpListenSock_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // 启用 IP_TRANSPARENT 支持非本地绑定与接收策略路由重定向流量
    setsockopt(tcpListenSock_, SOL_IP, IP_TRANSPARENT, &opt, sizeof(opt));

    struct timeval tv{};
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(tcpListenSock_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(tcpListenSock_, (sockaddr*)&addr, sizeof(addr)) != 0 || listen(tcpListenSock_, 512) != 0) {
        std::cerr << "[TProxy] Failed to bind/listen TCP socket on port " << port << std::endl;
        closesocket(tcpListenSock_);
        tcpListenSock_ = INVALID_SOCKET;
        return;
    }

    while (running_.load()) {
        sockaddr_in clientAddr{};
        socklen_t clientLen = sizeof(clientAddr);
        SOCKET clientSocket = accept(tcpListenSock_, (sockaddr*)&clientAddr, &clientLen);
        if (clientSocket == INVALID_SOCKET) {
            if (!running_.load()) break;
            continue;
        }

        char clientIP[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, sizeof(clientIP));

        // 设置读写超时与 TCP_NODELAY
        struct timeval tv{30, 0};
        setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        int nodelay = 1;
        setsockopt(clientSocket, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

        // 1. 检验来源与重定向合法性：仅本机可直接访问，外部严禁直接连接透明代理端口
        bool isLocalhost = (clientAddr.sin_addr.s_addr == htonl(INADDR_LOOPBACK));

        // 提取客户端原本想要访问的原始目标地址 (SO_ORIGINAL_DST)
        sockaddr_in origDst{};
        socklen_t origLen = sizeof(origDst);
        std::string targetIP = "";
        int targetPort = 0;

        if (!isLocalhost) {
            // 外部来源必须是经过防火墙重定向的合法透明代理流量，严禁外部直接访问 TProxy 端口
            if (getsockopt(clientSocket, SOL_IP, SO_ORIGINAL_DST, &origDst, &origLen) != 0) {
                closesocket(clientSocket);
                continue;
            }
            int origPort = ntohs(origDst.sin_port);
            if (origPort == port || origPort == 0) {
                // 原始目标端口为透明代理端口本身，说明是外部直接连接，严禁直接访问
                closesocket(clientSocket);
                continue;
            }
            char ipBuf[INET_ADDRSTRLEN] = {};
            inet_ntop(AF_INET, &origDst.sin_addr, ipBuf, sizeof(ipBuf));
            targetIP = ipBuf;
            targetPort = origPort;
        } else {
            // 本机访问 (127.0.0.1)：优先从 SO_ORIGINAL_DST 读取原始目标，若无则容许从 getsockname 读取
            if (getsockopt(clientSocket, SOL_IP, SO_ORIGINAL_DST, &origDst, &origLen) == 0 &&
                ntohs(origDst.sin_port) != port && ntohs(origDst.sin_port) != 0) {
                char ipBuf[INET_ADDRSTRLEN] = {};
                inet_ntop(AF_INET, &origDst.sin_addr, ipBuf, sizeof(ipBuf));
                targetIP = ipBuf;
                targetPort = ntohs(origDst.sin_port);
            } else {
                sockaddr_in localAddr{};
                socklen_t localLen = sizeof(localAddr);
                if (getsockname(clientSocket, (sockaddr*)&localAddr, &localLen) == 0) {
                    char ipBuf[INET_ADDRSTRLEN] = {};
                    inet_ntop(AF_INET, &localAddr.sin_addr, ipBuf, sizeof(ipBuf));
                    targetIP = ipBuf;
                    targetPort = ntohs(localAddr.sin_port);
                }
            }
        }

        if (targetIP.empty() || targetPort == 0 || targetPort == port) {
            closesocket(clientSocket);
            continue;
        }

        std::thread(&TProxyServer::HandleTcpClient, this, clientSocket, clientIP, targetIP, targetPort).detach();
    }
}

void TProxyServer::HandleTcpClient(SOCKET clientSocket, const std::string& clientIP,
                                  const std::string& targetIP, int targetPort) {
    const std::string inboundType = "透明代理";

    // 1. 基于客户端源 IP 识别局域网设备绑定的用户与配额
    UserInfo user;
    if (!UserManager::Instance().AuthenticateByIP(clientIP, user)) {
        ConnectionLogger::Instance().Log(user.username, clientIP, targetIP, targetPort, "TPROXY_REJECT", "设备未授权或配额超限", inboundType);
        closesocket(clientSocket);
        return;
    }

    // 2. 尝试从客户端首包嗅探目标域名 (TLS SNI 或 HTTP Host)
    std::string targetDomain = "";
    char peekBuf[2048] = {};
    struct pollfd pfd{};
    pfd.fd = clientSocket;
    pfd.events = POLLIN;
    if (poll(&pfd, 1, 350) > 0 && (pfd.revents & POLLIN)) {
        int peekLen = recv(clientSocket, peekBuf, sizeof(peekBuf), MSG_PEEK);
        if (peekLen > 0) {
            targetDomain = SniffDomain(peekBuf, peekLen);
        }
    }

    std::string displayTarget = targetDomain.empty() ? targetIP : targetDomain;

    // 3. 路由分流规则匹配 (真实域名 + 目标 IP 结合评估)
    std::string matchedGroup;
    bool isFallback = false;
    int proxyId = RuleManager::Instance().GetMatchingProxyId(targetIP, targetDomain, &matchedGroup, &isFallback);
    if (proxyId == -2) { // 阻断规则
        ConnectionLogger::Instance().Log(user.username, clientIP, displayTarget, targetPort, "TPROXY_BLOCK", "防火墙规则阻断", inboundType);
        closesocket(clientSocket);
        return;
    }

    // 4. 向上游建立连接 (走代理时优先传递嗅探到的真实域名由上游节点无污染解析；若直连或无域名则直连真实 IP)
    std::string upstreamTarget = (proxyId == 0 || targetDomain.empty()) ? targetIP : targetDomain;
    auto connRes = ProxyServer::Instance().ConnectWithFallback(proxyId, upstreamTarget, targetPort, matchedGroup, isFallback);
    if (connRes.socket == INVALID_SOCKET) {
        std::string failReason = (proxyId == 0 || connRes.description.find("直连") != std::string::npos)
                                     ? "直连连接超时"
                                     : "上游连接超时";
        ConnectionLogger::Instance().Log(user.username, clientIP, displayTarget, targetPort, "TPROXY_FAILED", failReason, inboundType);
        closesocket(clientSocket);
        return;
    }

    // 5. 注册实时连接记录与日志 (接入类型统一显示为: "透明代理")
    uint64_t connId = RealtimeConnectionManager::Instance().AddConnection(
        user.username, clientIP, displayTarget, targetPort, connRes.description, clientSocket, connRes.socket, inboundType);
    ConnectionLogger::Instance().Log(user.username, clientIP, displayTarget, targetPort, "TPROXY_TCP", connRes.description, inboundType);

    // 6. 启动全双工流式转发并统计流量
    ProxyServer::Instance().RelayData(clientSocket, connRes.socket, user.id, connRes.portId, connId);
}

void TProxyServer::UdpListenerThread(int port) {
#ifdef SOCK_CLOEXEC
    udpListenSock_ = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
#else
    udpListenSock_ = socket(AF_INET, SOCK_DGRAM, 0);
#endif
    if (udpListenSock_ == INVALID_SOCKET) return;

    int opt = 1;
    setsockopt(udpListenSock_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(udpListenSock_, SOL_IP, IP_TRANSPARENT, &opt, sizeof(opt));
    setsockopt(udpListenSock_, SOL_IP, IP_RECVORIGDSTADDR, &opt, sizeof(opt));

    struct timeval tv{};
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(udpListenSock_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(udpListenSock_, (sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(udpListenSock_);
        udpListenSock_ = INVALID_SOCKET;
        return;
    }

    char buf[4096];
    char ctrlBuf[1024];

    while (running_.load()) {
        iovec iov[1];
        iov[0].iov_base = buf;
        iov[0].iov_len = sizeof(buf);

        sockaddr_in clientAddr{};
        msghdr msg{};
        msg.msg_name = &clientAddr;
        msg.msg_namelen = sizeof(clientAddr);
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctrlBuf;
        msg.msg_controllen = sizeof(ctrlBuf);

        ssize_t n = recvmsg(udpListenSock_, &msg, 0);
        if (n <= 0) {
            if (!running_.load()) break;
            continue;
        }

        // 解析辅助数据中的原始目标地址
        sockaddr_in origDst{};
        bool hasOrigDst = false;
        for (cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVORIGDSTADDR) {
                std::memcpy(&origDst, CMSG_DATA(cmsg), sizeof(sockaddr_in));
                hasOrigDst = true;
                break;
            }
        }

        if (hasOrigDst) {
            bool isLocalhost = (clientAddr.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
            int origPort = ntohs(origDst.sin_port);
            if (!isLocalhost && (origPort == port || origPort == 0)) {
                // 外部直接发送至透明代理端口，严禁直接访问，直接忽略丢弃
                continue;
            }
            UdpRelayManager::Instance().HandleTransparentUdp(udpListenSock_, clientAddr, origDst, buf, n);
        }
    }
}
