#include "UdpRelayManager.h"
#include "ProxyServer.h"
#include "Rules.h"
#include "UserManager.h"
#include "TrafficMonitor.h"
#include "ConnectionLogger.h"
#include "RealtimeConnectionManager.h"
#include "ClashManager.h"
#include "Utils.h"

#include <iostream>
#include <cstring>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <algorithm>

namespace {

// 解析 DNS UDP 53 请求报文中的首个查询域名与查询类型 (QTYPE)
std::string ParseDnsQuery(const char* data, size_t len, uint16_t* outQType = nullptr, size_t* outQuestionEnd = nullptr) {
    if (outQType) *outQType = 0;
    if (outQuestionEnd) *outQuestionEnd = 0;
    if (len < 12) return "";
    size_t offset = 12;
    std::string domain;
    while (offset < len) {
        uint8_t labelLen = static_cast<uint8_t>(data[offset++]);
        if (labelLen == 0) break;
        if (labelLen > 63 || offset + labelLen > len) return "";
        if (!domain.empty()) domain += ".";
        for (size_t i = 0; i < labelLen; ++i) {
            char c = data[offset + i];
            if (!isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_') return "";
            domain += static_cast<char>(::tolower(static_cast<unsigned char>(c)));
        }
        offset += labelLen;
    }
    if (offset + 4 <= len) {
        if (outQType) {
            *outQType = (static_cast<uint16_t>(static_cast<uint8_t>(data[offset])) << 8) |
                        static_cast<uint16_t>(static_cast<uint8_t>(data[offset + 1]));
        }
        if (outQuestionEnd) {
            *outQuestionEnd = offset + 4;
        }
    }
    return domain;
}

uint16_t ComputeChecksum16(const void* data, size_t len) {
    uint32_t sum = 0;
    const uint16_t* ptr = reinterpret_cast<const uint16_t*>(data);
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len > 0) {
        uint16_t last = 0;
        *reinterpret_cast<uint8_t*>(&last) = *reinterpret_cast<const uint8_t*>(ptr);
        sum += last;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

uint16_t ComputeUdpChecksum(uint32_t saddr, uint32_t daddr, const uint8_t* udpPkt, size_t udpLen) {
    uint32_t sum = 0;
    const uint16_t* s = reinterpret_cast<const uint16_t*>(&saddr);
    const uint16_t* d = reinterpret_cast<const uint16_t*>(&daddr);
    sum += s[0];
    sum += s[1];
    sum += d[0];
    sum += d[1];
    sum += htons(IPPROTO_UDP);
    sum += htons(static_cast<uint16_t>(udpLen));

    const uint16_t* ptr = reinterpret_cast<const uint16_t*>(udpPkt);
    size_t len = udpLen;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len > 0) {
        uint16_t last = 0;
        *reinterpret_cast<uint8_t*>(&last) = *reinterpret_cast<const uint8_t*>(ptr);
        sum += last;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    uint16_t res = static_cast<uint16_t>(~sum);
    return res == 0 ? 0xFFFF : res;
}

// 临时创建 IP_TRANSPARENT 套接字以原始目标地址 origDst 作为源地址回传 UDP 响应并立即关闭；
// 若 origDst 为路由器本机已监听端口（如 dnsmasq 占用的 10.0.0.254:53）导致 bind 返回 EADDRINUSE，
// 则自动通过 SOCK_RAW 构造原始 IPv4+UDP 报文以 origDst 源地址精准回包。
void SendTransparentUdpReply(SOCKET fallbackSock, const sockaddr_in& origDst, const sockaddr_in& clientAddr,
                             const char* payload, size_t payloadLen) {
    int sockFlags = 0;
#ifdef SOCK_CLOEXEC
    sockFlags |= SOCK_CLOEXEC;
#endif
    SOCKET txSock = socket(AF_INET, SOCK_DGRAM | sockFlags, 0);
    ssize_t sent = -1;
    if (txSock != INVALID_SOCKET) {
        int opt = 1;
        setsockopt(txSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
        setsockopt(txSock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
        setsockopt(txSock, SOL_IP, IP_TRANSPARENT, &opt, sizeof(opt));
        int mark = 0xff;
        setsockopt(txSock, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
        if (bind(txSock, reinterpret_cast<const sockaddr*>(&origDst), sizeof(origDst)) == 0) {
            sent = sendto(txSock, payload, payloadLen, 0,
                          reinterpret_cast<const sockaddr*>(&clientAddr), sizeof(clientAddr));
        }
        closesocket(txSock);
    }
    if (sent < 0) {
        SOCKET rawSock = socket(AF_INET, SOCK_RAW | sockFlags, IPPROTO_RAW);
        if (rawSock != INVALID_SOCKET) {
            int one = 1;
            setsockopt(rawSock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
            int mark = 0xff;
            setsockopt(rawSock, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));

            size_t udpLen = sizeof(udphdr) + payloadLen;
            size_t totalLen = sizeof(iphdr) + udpLen;
            std::vector<uint8_t> pkt(totalLen, 0);

            auto* iph = reinterpret_cast<iphdr*>(pkt.data());
            iph->ihl = 5;
            iph->version = 4;
            iph->tos = 0;
            iph->tot_len = htons(static_cast<uint16_t>(totalLen));
            iph->id = htons(0x524c);
            iph->frag_off = 0;
            iph->ttl = 64;
            iph->protocol = IPPROTO_UDP;
            iph->saddr = origDst.sin_addr.s_addr;
            iph->daddr = clientAddr.sin_addr.s_addr;
            iph->check = 0;
            iph->check = ComputeChecksum16(iph, sizeof(iphdr));

            auto* udph = reinterpret_cast<udphdr*>(pkt.data() + sizeof(iphdr));
            udph->source = origDst.sin_port;
            udph->dest = clientAddr.sin_port;
            udph->len = htons(static_cast<uint16_t>(udpLen));
            udph->check = 0;
            std::memcpy(pkt.data() + sizeof(iphdr) + sizeof(udphdr), payload, payloadLen);
            udph->check = ComputeUdpChecksum(iph->saddr, iph->daddr, pkt.data() + sizeof(iphdr), udpLen);

            sent = sendto(rawSock, pkt.data(), pkt.size(), 0,
                          reinterpret_cast<const sockaddr*>(&clientAddr), sizeof(clientAddr));
            closesocket(rawSock);
        }
    }
    if (sent < 0 && fallbackSock != INVALID_SOCKET) {
        sendto(fallbackSock, payload, payloadLen, 0,
               reinterpret_cast<const sockaddr*>(&clientAddr), sizeof(clientAddr));
    }
}

// 封装 SOCKS5 UDP 请求报文 (RFC 1928 Section 7)
std::string BuildSocks5UdpPacket(const std::string& host, int port, const char* payload, size_t payloadLen) {
    std::string packet;
    packet.push_back(0x00); // RSV
    packet.push_back(0x00); // RSV
    packet.push_back(0x00); // FRAG: 0x00 不分片

    struct in_addr addr4;
    if (inet_pton(AF_INET, host.c_str(), &addr4) == 1) {
        packet.push_back(0x01); // IPv4
        packet.append(reinterpret_cast<const char*>(&addr4.s_addr), 4);
    } else {
        packet.push_back(0x03); // 域名
        packet.push_back(static_cast<char>(host.length()));
        packet.append(host);
    }

    uint16_t np = htons(static_cast<uint16_t>(port));
    packet.append(reinterpret_cast<const char*>(&np), 2);
    packet.append(payload, payloadLen);
    return packet;
}

// 解包 SOCKS5 UDP 应答报文，提取内部真实应用负载
bool ParseSocks5UdpPacket(const char* data, size_t len, const char*& outPayload, size_t& outPayloadLen) {
    if (len < 10 || data[0] != 0 || data[1] != 0) return false;
    uint8_t atyp = static_cast<uint8_t>(data[3]);
    size_t headerLen = 0;
    if (atyp == 0x01) { // IPv4
        headerLen = 10;
    } else if (atyp == 0x03) { // 域名
        if (len < 5) return false;
        uint8_t domLen = static_cast<uint8_t>(data[4]);
        headerLen = 4 + 1 + domLen + 2;
    } else if (atyp == 0x04) { // IPv6
        headerLen = 22;
    } else {
        return false;
    }
    if (len < headerLen) return false;
    outPayload = data + headerLen;
    outPayloadLen = len - headerLen;
    return true;
}

} // namespace

UdpRelayManager& UdpRelayManager::Instance() {
    static UdpRelayManager instance;
    return instance;
}

UdpRelayManager::UdpRelayManager() {
    Initialize();
}

UdpRelayManager::~UdpRelayManager() {
    Stop();
}

bool UdpRelayManager::Initialize() {
    if (running_.load()) return true;
    running_.store(true);
    scavengerThread_ = std::thread(&UdpRelayManager::ScavengerThread, this);
    return true;
}

void UdpRelayManager::Stop() {
    if (!running_.load()) return;
    running_.store(false);

    {
        std::lock_guard<std::mutex> lock(sessionsMutex_);
        for (auto& pair : sessions_) {
            pair.second->running.store(false);
            if (pair.second->upstreamSock != INVALID_SOCKET) {
                shutdown(pair.second->upstreamSock, SHUT_RDWR);
                closesocket(pair.second->upstreamSock);
                pair.second->upstreamSock = INVALID_SOCKET;
            }
            if (pair.second->tcpControlSock != INVALID_SOCKET) {
                shutdown(pair.second->tcpControlSock, SHUT_RDWR);
                closesocket(pair.second->tcpControlSock);
                pair.second->tcpControlSock = INVALID_SOCKET;
            }
            if (pair.second->spoofSock != INVALID_SOCKET) {
                shutdown(pair.second->spoofSock, SHUT_RDWR);
                closesocket(pair.second->spoofSock);
                pair.second->spoofSock = INVALID_SOCKET;
            }
            if (pair.second->socksClientUdpSock != INVALID_SOCKET) {
                shutdown(pair.second->socksClientUdpSock, SHUT_RDWR);
                closesocket(pair.second->socksClientUdpSock);
                pair.second->socksClientUdpSock = INVALID_SOCKET;
            }
            if (pair.second->workerThread.joinable()) {
                pair.second->workerThread.detach();
            }
        }
        sessions_.clear();
    }

    if (scavengerThread_.joinable()) {
        scavengerThread_.join();
    }
}

bool UdpRelayManager::EstablishUpstreamChannel(int preferredProxyId, const std::string& targetGroup,
                                               SOCKET& outTcpCtrl, sockaddr_in& outRelayUdpAddr,
                                               std::string& outDesc, int& outPortId, bool& outIsDirect,
                                               bool isFallback) {
    outTcpCtrl = INVALID_SOCKET;
    outIsDirect = false;
    outPortId = 0;

    if (preferredProxyId == 0) {
        outIsDirect = true;
        outDesc = isFallback ? "DIRECT 兜底直连" : "DIRECT 直连";
        return true;
    }

    auto tryConnectPort = [&](const ProxyPort& p, const std::string& prefix) -> bool {
        if (!p.enabled) return false;
        std::string upHost, upUser, upPass;
        int upPort = 0;
        if (p.upstreamType == "clash") {
            int localSocks = ClashManager::Instance().GetLocalSocksPort(p.id);
            if (localSocks <= 0 && !p.clashConfig.empty()) {
                localSocks = ClashManager::Instance().StartClash(p.id, p.clashConfig);
            }
            if (localSocks <= 0) return false;
            upHost = "127.0.0.1";
            upPort = localSocks;
        } else if (p.upstreamType == "socks5") {
            upHost = p.upstreamHost;
            upPort = p.upstreamPort;
            upUser = p.upstreamUser;
            upPass = p.upstreamPass;
        } else {
            return false;
        }

        sockaddr_in relayAddr{};
        SOCKET tcp = ConnectUpstreamSocks5Udp(upHost, upPort, upUser, upPass, relayAddr);
        if (tcp == INVALID_SOCKET && p.upstreamType == "clash" && !p.clashConfig.empty()) {
            ClashManager::Instance().StopClash(p.id);
            int localSocks = ClashManager::Instance().StartClash(p.id, p.clashConfig);
            if (localSocks > 0) {
                upPort = localSocks;
                tcp = ConnectUpstreamSocks5Udp(upHost, upPort, upUser, upPass, relayAddr);
            }
        }
        if (tcp != INVALID_SOCKET) {
            outTcpCtrl = tcp;
            outRelayUdpAddr = relayAddr;
            outPortId = p.id;
            outDesc = prefix + (p.description.empty() ? p.upstreamHost : p.description);
            outIsDirect = false;
            return true;
        }
        return false;
    };

    // 1. 指定节点优先尝试
    if (preferredProxyId > 0) {
        ProxyPort p;
        if (Database::Instance().GetProxyPortById(preferredProxyId, p) && p.enabled) {
            if (tryConnectPort(p, isFallback ? "[兜底] " : ("[" + p.groupName + "] "))) return true;
            // 节点连接失败且有所属具体组，尝试同组其他节点
            if (!p.groupName.empty() && p.groupName != "默认") {
                auto ports = Database::Instance().GetAllProxyPorts();
                for (const auto& alt : ports) {
                    if (alt.enabled && alt.id != p.id && alt.groupName == p.groupName) {
                        if (tryConnectPort(alt, isFallback ? "[兜底:" + alt.groupName + "] " : ("[" + alt.groupName + "] "))) return true;
                    }
                }
            }
        }
    }

    // 2. 按分组轮询候选节点
    if (!targetGroup.empty() || preferredProxyId == -3) {
        auto ports = Database::Instance().GetAllProxyPorts();
        for (const auto& p : ports) {
            if (p.enabled && (targetGroup.empty() || p.groupName == targetGroup)) {
                if (tryConnectPort(p, isFallback ? "[兜底:" + p.groupName + "] " : ("[" + p.groupName + "] "))) return true;
            }
        }
    }

    // 3. 严格规则控制：如果命中明确策略规则（非兜底规则，!isFallback），严格执行分流策略！
    if (!isFallback) {
        return false;
    }

    // 4. 兜底规则回退尝试
    RoutingRule fallbackRule;
    if (Database::Instance().GetFallbackRule(fallbackRule) && fallbackRule.enabled) {
        if (fallbackRule.proxyId == 0) {
            outIsDirect = true;
            outDesc = "DIRECT 兜底直连";
            return true;
        } else if (fallbackRule.proxyId > 0) {
            ProxyPort p;
            if (Database::Instance().GetProxyPortById(fallbackRule.proxyId, p) && p.enabled) {
                if (tryConnectPort(p, "[兜底] ")) return true;
            }
        } else if (!fallbackRule.targetGroup.empty() || fallbackRule.proxyId == -3) {
            auto ports = Database::Instance().GetAllProxyPorts();
            for (const auto& p : ports) {
                if (p.enabled && (fallbackRule.targetGroup.empty() || p.groupName == fallbackRule.targetGroup)) {
                    if (tryConnectPort(p, "[兜底:" + p.groupName + "] ")) return true;
                }
            }
        }
    }

    return false;
}

SOCKET UdpRelayManager::ConnectUpstreamSocks5Udp(const std::string& host, int port,
                                                const std::string& user, const std::string& pass,
                                                sockaddr_in& outRelayUdpAddr) {
    SOCKET s = ProxyServer::Instance().ConnectDirect(host, port);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    // 1. SOCKS5 协商认证
    bool hasAuth = !user.empty();
    if (hasAuth) {
        char req[4] = {0x05, 0x02, 0x00, 0x02};
        if (send(s, req, 4, 0) != 4) { closesocket(s); return INVALID_SOCKET; }
    } else {
        char req[3] = {0x05, 0x01, 0x00};
        if (send(s, req, 3, 0) != 3) { closesocket(s); return INVALID_SOCKET; }
    }

    char methodResp[2] = {};
    if (recv(s, methodResp, 2, 0) != 2 || (unsigned char)methodResp[0] != 0x05) {
        closesocket(s);
        return INVALID_SOCKET;
    }

    if (methodResp[1] == 0x02) {
        std::string authPayload;
        authPayload.push_back(0x01);
        authPayload.push_back((char)user.length());
        authPayload.append(user);
        authPayload.push_back((char)pass.length());
        authPayload.append(pass);
        if (send(s, authPayload.data(), authPayload.size(), 0) != (int)authPayload.size()) {
            closesocket(s);
            return INVALID_SOCKET;
        }
        char authResp[2] = {};
        if (recv(s, authResp, 2, 0) != 2 || authResp[1] != 0x00) {
            closesocket(s);
            return INVALID_SOCKET;
        }
    } else if (methodResp[1] != 0x00) {
        closesocket(s);
        return INVALID_SOCKET;
    }

    // 2. 发送 UDP ASSOCIATE 请求 (CMD 0x03)
    char assocReq[10] = {0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    if (send(s, assocReq, 10, 0) != 10) {
        closesocket(s);
        return INVALID_SOCKET;
    }

    char assocResp[4] = {};
    if (recv(s, assocResp, 4, 0) != 4 || (unsigned char)assocResp[0] != 0x05 || assocResp[1] != 0x00) {
        closesocket(s);
        return INVALID_SOCKET;
    }

    int atyp = assocResp[3];
    sockaddr_in relayAddr{};
    relayAddr.sin_family = AF_INET;

    if (atyp == 0x01) { // IPv4
        char ipPort[6] = {};
        if (recv(s, ipPort, 6, 0) != 6) { closesocket(s); return INVALID_SOCKET; }
        std::memcpy(&relayAddr.sin_addr.s_addr, ipPort, 4);
        std::memcpy(&relayAddr.sin_port, ipPort + 4, 2);
    } else if (atyp == 0x03) { // 域名
        unsigned char dlen = 0;
        if (recv(s, (char*)&dlen, 1, 0) != 1) { closesocket(s); return INVALID_SOCKET; }
        std::string dom(dlen, '\0');
        if (recv(s, &dom[0], dlen, 0) != (int)dlen) { closesocket(s); return INVALID_SOCKET; }
        uint16_t p = 0;
        if (recv(s, (char*)&p, 2, 0) != 2) { closesocket(s); return INVALID_SOCKET; }
        inet_pton(AF_INET, dom.c_str(), &relayAddr.sin_addr);
        relayAddr.sin_port = p;
    } else {
        closesocket(s);
        return INVALID_SOCKET;
    }

    // 如果返回的 BND.ADDR 为 0.0.0.0，替换为上游主机 IP
    if (relayAddr.sin_addr.s_addr == INADDR_ANY) {
        inet_pton(AF_INET, host.c_str(), &relayAddr.sin_addr);
    }

    outRelayUdpAddr = relayAddr;
    return s;
}

void UdpRelayManager::HandleTransparentUdp(SOCKET udpListenSock, const sockaddr_in& clientAddr,
                                           const sockaddr_in& origDst, const char* data, size_t len) {
    char clientIP[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, sizeof(clientIP));
    int clientPort = ntohs(clientAddr.sin_port);

    char targetIP[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &origDst.sin_addr, targetIP, sizeof(targetIP));
    int targetPort = ntohs(origDst.sin_port);

    if (targetPort == 443) {
        // 忽略 QUIC (UDP 443)，促使客户端迅速降级为 TCP 443 以进行精确的 SNI 嗅探
        return;
    }

    // 1. 用户与设备权限鉴权
    UserInfo user;
    if (!UserManager::Instance().AuthenticateByIP(clientIP, user)) {
        return;
    }

    // 2. DNS 域名嗅探 (目标端口为 53 时提取真实被查询域名与查询类型)
    uint16_t dnsQType = 0;
    size_t dnsQuestionEnd = 0;
    std::string targetDomain;
    if (targetPort == 53) {
        targetDomain = ParseDnsQuery(data, len, &dnsQType, &dnsQuestionEnd);
    }

    std::string displayTarget = targetDomain.empty() ? targetIP : targetDomain;

    // 3. 路由规则匹配 (当为 DNS 查询且已提取出被查询域名时，以被查询域名匹配分流规则，忽略 DNS 服务器本身的私网/国内 IP)
    std::string matchIP = (targetPort == 53 && !targetDomain.empty()) ? "" : std::string(targetIP);
    std::string matchedGroup;
    bool isFallback = false;
    int proxyId = RuleManager::Instance().GetMatchingProxyId(matchIP, targetDomain, &matchedGroup, &isFallback);
    if (proxyId == -2) { // 防火墙阻断
        return;
    }

    // 4. 针对走代理分流的 DNS 查询 (UDP 53 && proxyId != 0)：
    //    (a) 若查询类型为 AAAA (28) 或 HTTPS/SVCB (65)，立即返回标准空应答 (NOERROR, ANCOUNT=0)，
    //        防止客户端使用未代理的 IPv6、QUIC 或 ECH 加密 SNI；
    //    (b) 其余查询 (如 A 记录) 通过代理隧道以 DNS-over-TCP 方式向 8.8.8.8:53 / 1.1.1.1:53 进行无污染解析，
    //        兼容所有代理协议（包括不支持 UDP 的节点或 HTTP/HTTPS 代理）并彻底消除 GFW DNS 污染。
    if (targetPort == 53 && proxyId != 0 && !targetDomain.empty()) {
        if ((dnsQType == 28 || dnsQType == 65) && dnsQuestionEnd >= 16 && dnsQuestionEnd <= len) {
            std::vector<char> emptyReply(data, data + dnsQuestionEnd);
            emptyReply[2] = static_cast<char>(0x81); // QR=1, Opcode=0, RD=1
            emptyReply[3] = static_cast<char>(0x80); // RA=1, RCODE=0 (NOERROR)
            emptyReply[4] = 0x00; emptyReply[5] = 0x01; // QDCOUNT = 1
            emptyReply[6] = 0x00; emptyReply[7] = 0x00; // ANCOUNT = 0
            emptyReply[8] = 0x00; emptyReply[9] = 0x00; // NSCOUNT = 0
            emptyReply[10] = 0x00; emptyReply[11] = 0x00; // ARCOUNT = 0
            SendTransparentUdpReply(udpListenSock, origDst, clientAddr, emptyReply.data(), emptyReply.size());
            return;
        }

        std::string queryCopy(data, len);
        int uid = user.id;
        std::string uname = user.username;
        std::string cip = clientIP;
        std::thread([udpListenSock, clientAddr, origDst, queryCopy, proxyId, matchedGroup, isFallback, uid, uname, cip, displayTarget]() {
            auto connRes = ProxyServer::Instance().ConnectWithFallback(proxyId, "8.8.8.8", 53, matchedGroup, isFallback);
            if (connRes.socket == INVALID_SOCKET) {
                connRes = ProxyServer::Instance().ConnectWithFallback(proxyId, "1.1.1.1", 53, matchedGroup, isFallback);
            }
            if (connRes.socket == INVALID_SOCKET) return;

            struct timeval tv{};
            tv.tv_sec = 4;
            tv.tv_usec = 0;
            setsockopt(connRes.socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(connRes.socket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

            uint16_t qlen = htons(static_cast<uint16_t>(queryCopy.size()));
            std::string tcpReq;
            tcpReq.reserve(2 + queryCopy.size());
            tcpReq.append(reinterpret_cast<const char*>(&qlen), 2);
            tcpReq.append(queryCopy);

            if (send(connRes.socket, tcpReq.data(), tcpReq.size(), MSG_NOSIGNAL) == static_cast<ssize_t>(tcpReq.size())) {
                uint8_t lenBuf[2] = {};
                ssize_t r1 = recv(connRes.socket, reinterpret_cast<char*>(lenBuf), 2, MSG_WAITALL);
                if (r1 == 2) {
                    uint16_t respLen = (static_cast<uint16_t>(lenBuf[0]) << 8) | static_cast<uint16_t>(lenBuf[1]);
                    if (respLen >= 12 && respLen <= 4096) {
                        std::vector<char> respBuf(respLen);
                        ssize_t r2 = recv(connRes.socket, respBuf.data(), respLen, MSG_WAITALL);
                        if (r2 == static_cast<ssize_t>(respLen)) {
                            SendTransparentUdpReply(udpListenSock, origDst, clientAddr, respBuf.data(), respLen);
                            TrafficMonitor::Instance().RecordUpload(uid, connRes.portId, queryCopy.size());
                            TrafficMonitor::Instance().RecordDownload(uid, connRes.portId, respLen);
                            ConnectionLogger::Instance().Log(uname, cip, displayTarget, 53, "TPROXY_DNS", connRes.description, "透明代理");
                        }
                    }
                }
            }
            closesocket(connRes.socket);
        }).detach();
        return;
    }

    // 5. 获取或新建 UDP 会话
    std::string sessionKey = std::string(clientIP) + ":" + std::to_string(clientPort) + "_" +
                             targetIP + ":" + std::to_string(targetPort) + "_p" + std::to_string(proxyId);

    std::shared_ptr<UdpSession> session;
    bool isNewSession = false;

    {
        std::lock_guard<std::mutex> lock(sessionsMutex_);
        auto it = sessions_.find(sessionKey);
        if (it != sessions_.end() && it->second->running.load()) {
            session = it->second;
        } else {
            if (it != sessions_.end()) {
                it->second->running.store(false);
                if (it->second->workerThread.joinable()) {
                    it->second->workerThread.detach();
                }
            }
            session = std::make_shared<UdpSession>();
            session->sessionKey = sessionKey;
            session->clientAddr = clientAddr;
            session->origDst = origDst;
            session->isTransparent = true;
            session->userId = user.id;
            session->username = user.username;
            session->clientIP = clientIP;
            session->displayTarget = displayTarget;
            session->inboundType = "透明代理";

            int sockFlags = 0;
#ifdef SOCK_CLOEXEC
            sockFlags |= SOCK_CLOEXEC;
#endif

            if (proxyId == 0) { // 国内直连
                session->isDirect = true;
                session->proxyDesc = isFallback ? "DIRECT 兜底直连" : "DIRECT 直连";
                session->portId = 0;
                session->upstreamSock = socket(AF_INET, SOCK_DGRAM | sockFlags, 0);
            } else { // 代理转发
                SOCKET tcpCtrl = INVALID_SOCKET;
                sockaddr_in relayAddr{};
                bool isDirect = false;
                if (!EstablishUpstreamChannel(proxyId, matchedGroup, tcpCtrl, relayAddr, session->proxyDesc, session->portId, isDirect, isFallback)) {
                    return;
                }
                session->isDirect = isDirect;
                if (!isDirect) {
                    session->tcpControlSock = tcpCtrl;
                    session->upstreamRelayAddr = relayAddr;
                }
                session->upstreamSock = socket(AF_INET, SOCK_DGRAM | sockFlags, 0);
            }

            if (session->upstreamSock == INVALID_SOCKET) return;

            int mark = 0xff;
            setsockopt(session->upstreamSock, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
            session->spoofSock = INVALID_SOCKET;

            sessions_[sessionKey] = session;
            isNewSession = true;
        }
    }

    session->lastActive = std::chrono::steady_clock::now();

    // 6. 启动响应包监听线程
    if (isNewSession) {
        session->connId = RealtimeConnectionManager::Instance().AddConnection(
            session->username, session->clientIP, session->displayTarget,
            targetPort, session->proxyDesc,
            session->spoofSock, session->upstreamSock, session->inboundType, "UDP");

        ConnectionLogger::Instance().Log(session->username, session->clientIP, session->displayTarget,
                                         targetPort, "TPROXY_UDP", session->proxyDesc, session->inboundType);

        session->workerThread = std::thread([this, session, udpListenSock]() {
            try {
                char buf[65536];
                while (session->running.load() && running_.load()) {
                    struct pollfd pfd;
                    pfd.fd = session->upstreamSock;
                    pfd.events = POLLIN;

                    int pr = poll(&pfd, 1, 1000);
                    if (pr <= 0) {
                        auto now = std::chrono::steady_clock::now();
                        int idleSec = std::chrono::duration_cast<std::chrono::seconds>(now - session->lastActive).count();
                        if (idleSec > 45) break; // 45s 空闲超时退出
                        continue;
                    }

                    sockaddr_in fromAddr{};
                    socklen_t fromLen = sizeof(fromAddr);
                    ssize_t n = recvfrom(session->upstreamSock, buf, sizeof(buf), 0, (sockaddr*)&fromAddr, &fromLen);
                    if (n <= 0) break;

                    session->lastActive = std::chrono::steady_clock::now();

                    const char* payload = buf;
                    size_t payloadLen = n;

                    if (!session->isDirect) {
                        if (!ParseSocks5UdpPacket(buf, n, payload, payloadLen)) {
                            continue;
                        }
                    }

                    SendTransparentUdpReply(udpListenSock, session->origDst, session->clientAddr, payload, payloadLen);

                    TrafficMonitor::Instance().RecordDownload(session->userId, session->portId, payloadLen);
                    RealtimeConnectionManager::Instance().RecordTraffic(session->connId, 0, payloadLen);
                }
            } catch (const std::exception& e) {
                std::cerr << "[UdpRelay] Exception in workerThread: " << e.what() << std::endl;
            } catch (...) {
                std::cerr << "[UdpRelay] Unknown exception in workerThread" << std::endl;
            }

            RealtimeConnectionManager::Instance().CloseConnection(session->connId);
            session->running.store(false);
        });
        session->workerThread.detach();
    }

    // 7. 发送数据包至上游节点或目标服务器
    if (session->isDirect) {
        sockaddr_in directDst = origDst;
        if (targetPort == 53 && !targetDomain.empty()) {
            uint32_t ipHostOrder = ntohl(origDst.sin_addr.s_addr);
            bool isPrivateDst = ((ipHostOrder & 0xFF000000) == 0x0A000000) || // 10.0.0.0/8
                                ((ipHostOrder & 0xFFF00000) == 0xAC100000) || // 172.16.0.0/12
                                ((ipHostOrder & 0xFFFF0000) == 0xC0A80000) || // 192.168.0.0/16
                                ((ipHostOrder & 0xFF000000) == 0x7F000000);   // 127.0.0.0/8
            auto endsWith = [](const std::string& s, const std::string& suffix) {
                return s.size() >= suffix.size() &&
                       s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
            };
            bool isInternalDomain = (targetDomain.find('.') == std::string::npos) ||
                                    endsWith(targetDomain, ".lan") ||
                                    endsWith(targetDomain, ".local") ||
                                    endsWith(targetDomain, ".arpa") ||
                                    endsWith(targetDomain, ".internal") ||
                                    endsWith(targetDomain, ".home") ||
                                    endsWith(targetDomain, ".corp") ||
                                    endsWith(targetDomain, ".localdomain") ||
                                    endsWith(targetDomain, ".shanghaiit.com");
            if (isPrivateDst && !isInternalDomain) {
                // 当透明代理接收到发往本机/局域网 DNS (如 10.0.0.254:53) 的公网直连域名查询时，
                // 直接向公共国内 DNS (223.5.5.5:53) 发起解析，避免交回本机 dnsmasq 转发至主路由/内网 DNS 产生回环
                inet_pton(AF_INET, "223.5.5.5", &directDst.sin_addr);
            }
        }
        sendto(session->upstreamSock, data, len, 0, (sockaddr*)&directDst, sizeof(directDst));
    } else {
        std::string forwardHost = (targetPort == 53 || targetDomain.empty()) ? targetIP : targetDomain;
        auto packet = BuildSocks5UdpPacket(forwardHost, targetPort, data, len);
        sendto(session->upstreamSock, packet.data(), packet.size(), 0,
               (sockaddr*)&session->upstreamRelayAddr, sizeof(session->upstreamRelayAddr));
    }

    TrafficMonitor::Instance().RecordUpload(user.id, session->portId, len);
    RealtimeConnectionManager::Instance().RecordTraffic(session->connId, len, 0);
}

void UdpRelayManager::HandleSocks5UdpAssociate(SOCKET clientTcpSock, const std::string& clientIP,
                                              const ProxyPort& port, int userId,
                                              const std::string& username, const char* cmdBuf,
                                              std::shared_ptr<OpenSSLSession> tlsSession) {
    // 1. 读取客户端期望的 UDP 地址并打开本地 UDP 中继端口
    int addrType = cmdBuf[3];
    if (addrType == 0x01) { // IPv4
        char dummy[6];
        recv(clientTcpSock, dummy, 6, 0);
    } else if (addrType == 0x03) { // Domain
        unsigned char domLen = 0;
        recv(clientTcpSock, (char*)&domLen, 1, 0);
        std::string dummy(domLen + 2, '\0');
        recv(clientTcpSock, &dummy[0], domLen + 2, 0);
    } else {
        char dummy[18];
        recv(clientTcpSock, dummy, 18, 0);
    }

    int sockFlags = 0;
#ifdef SOCK_CLOEXEC
    sockFlags |= SOCK_CLOEXEC;
#endif

    SOCKET socksClientUdpSock = socket(AF_INET, SOCK_DGRAM | sockFlags, 0);
    if (socksClientUdpSock == INVALID_SOCKET) {
        char fail[10] = {0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        send(clientTcpSock, fail, 10, 0);
        closesocket(clientTcpSock);
        return;
    }

    sockaddr_in localAddr{};
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = INADDR_ANY;
    localAddr.sin_port = 0; // 系统分配空闲 UDP 端口
    bind(socksClientUdpSock, (sockaddr*)&localAddr, sizeof(localAddr));

    socklen_t localLen = sizeof(localAddr);
    getsockname(socksClientUdpSock, (sockaddr*)&localAddr, &localLen);
    uint16_t assignedPort = ntohs(localAddr.sin_port);

    sockaddr_in tcpLocalAddr{};
    socklen_t tcpLocalLen = sizeof(tcpLocalAddr);
    getsockname(clientTcpSock, (sockaddr*)&tcpLocalAddr, &tcpLocalLen);

    // 2. 向客户端应答 SOCKS5 成功并提供中继 UDP 端口 (RFC 1928)
    unsigned char resp[10] = {0x05, 0x00, 0x00, 0x01};
    std::memcpy(&resp[4], &tcpLocalAddr.sin_addr.s_addr, 4);
    uint16_t np = htons(assignedPort);
    std::memcpy(&resp[8], &np, 2);
    send(clientTcpSock, (char*)resp, 10, 0);

    // 3. 进入 SOCKS5 UDP 关联转发循环，以 TCP 控制连接的存活为基准
    char buf[65536];
    sockaddr_in clientUdpEndpoint{};

    // 维护该 SOCKS5 客户端的会话
    std::map<std::string, std::shared_ptr<UdpSession>> socksSessions;

    while (running_.load()) {
        struct pollfd pfds[2];
        pfds[0].fd = clientTcpSock;
        pfds[0].events = POLLIN;
        pfds[1].fd = socksClientUdpSock;
        pfds[1].events = POLLIN;

        int pr = poll(pfds, 2, 1000);
        if (pr < 0) break;

        // 检查 TCP 控制连接是否断开
        if (pfds[0].revents & (POLLIN | POLLERR | POLLHUP | POLLNVAL)) {
            char probe = 0;
            int r = recv(clientTcpSock, &probe, 1, MSG_PEEK);
            if (r <= 0) break; // 客户端 TCP 已关闭，按 RFC 规范终止对应 UDP 关联
        }

        // 处理客户端发送的 UDP 数据包
        if (pfds[1].revents & POLLIN) {
            sockaddr_in fromAddr{};
            socklen_t fromLen = sizeof(fromAddr);
            int n = recvfrom(socksClientUdpSock, buf, sizeof(buf), 0, (sockaddr*)&fromAddr, &fromLen);
            if (n <= 0) continue;

            clientUdpEndpoint = fromAddr;

            if (n < 10 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0) continue; // 忽略分片

            int atyp = static_cast<uint8_t>(buf[3]);
            std::string targetHost;
            int targetPort = 0;
            size_t payloadOffset = 0;

            if (atyp == 0x01) { // IPv4
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, buf + 4, ip, sizeof(ip));
                targetHost = ip;
                targetPort = ntohs(*reinterpret_cast<uint16_t*>(buf + 8));
                payloadOffset = 10;
            } else if (atyp == 0x03) { // 域名
                uint8_t domLen = static_cast<uint8_t>(buf[4]);
                if (n < 4 + 1 + domLen + 2) continue;
                targetHost = std::string(buf + 5, domLen);
                targetPort = ntohs(*reinterpret_cast<uint16_t*>(buf + 5 + domLen));
                payloadOffset = 4 + 1 + domLen + 2;
            } else {
                continue;
            }

            if (n <= (int)payloadOffset) continue;
            const char* payload = buf + payloadOffset;
            size_t payloadLen = n - payloadOffset;

            std::string targetDomain;
            std::string targetIP;
            struct in_addr in;
            if (inet_pton(AF_INET, targetHost.c_str(), &in) == 1) {
                targetIP = targetHost;
                if (targetPort == 53) targetDomain = ParseDnsQuery(payload, payloadLen);
            } else {
                targetDomain = targetHost;
            }

            // 规则分流匹配
            std::string matchedGroup;
            bool isFallback = false;
            int proxyId = RuleManager::Instance().GetMatchingProxyId(targetIP, targetDomain, &matchedGroup, &isFallback);
            if (proxyId == -2) continue; // 阻断

            std::string sessKey = targetHost + ":" + std::to_string(targetPort);
            std::shared_ptr<UdpSession> s;
            auto it = socksSessions.find(sessKey);
            if (it != socksSessions.end() && it->second->running.load()) {
                s = it->second;
            } else {
                s = std::make_shared<UdpSession>();
                s->sessionKey = sessKey;
                s->isTransparent = false;
                s->socksClientUdpSock = socksClientUdpSock;
                s->userId = userId;
                s->portId = port.id;
                s->username = username;
                s->clientIP = clientIP;
                s->displayTarget = targetHost;
                s->inboundType = "SOCKS5";

                if (proxyId == 0) {
                    s->isDirect = true;
                    s->proxyDesc = isFallback ? "DIRECT 兜底直连" : "DIRECT 直连";
                    s->upstreamSock = socket(AF_INET, SOCK_DGRAM | sockFlags, 0);
                } else {
                    SOCKET tcpCtrl = INVALID_SOCKET;
                    sockaddr_in relayAddr{};
                    bool isDirect = false;
                    if (!EstablishUpstreamChannel(proxyId, matchedGroup, tcpCtrl, relayAddr, s->proxyDesc, s->portId, isDirect, isFallback)) {
                        continue;
                    }
                    s->isDirect = isDirect;
                    if (!isDirect) {
                        s->tcpControlSock = tcpCtrl;
                        s->upstreamRelayAddr = relayAddr;
                    }
                    s->upstreamSock = socket(AF_INET, SOCK_DGRAM | sockFlags, 0);
                }

                if (s->upstreamSock == INVALID_SOCKET) continue;

                s->connId = RealtimeConnectionManager::Instance().AddConnection(
                    s->username, s->clientIP, s->displayTarget,
                    targetPort, s->proxyDesc,
                    socksClientUdpSock, s->upstreamSock, s->inboundType, "UDP");

                socksSessions[sessKey] = s;
                ConnectionLogger::Instance().Log(s->username, s->clientIP, s->displayTarget,
                                                 targetPort, "SOCKS5_UDP", s->proxyDesc, s->inboundType);

                // 启动此上游目标的接收响应线程
                s->workerThread = std::thread([this, s, targetHost, targetPort, clientTcpSock]() {
                    try {
                        char respBuf[65536];
                        while (s->running.load() && running_.load()) {
                            struct pollfd upfd;
                            upfd.fd = s->upstreamSock;
                            upfd.events = POLLIN;

                            int upr = poll(&upfd, 1, 1000);
                            if (upr <= 0) {
                                auto now = std::chrono::steady_clock::now();
                                if (std::chrono::duration_cast<std::chrono::seconds>(now - s->lastActive).count() > 45) {
                                    break;
                                }
                                continue;
                            }

                            sockaddr_in fromAddr{};
                            socklen_t fromLen = sizeof(fromAddr);
                            int un = recvfrom(s->upstreamSock, respBuf, sizeof(respBuf), 0, (sockaddr*)&fromAddr, &fromLen);
                            if (un <= 0) break;

                            s->lastActive = std::chrono::steady_clock::now();

                            const char* respPayload = respBuf;
                            size_t respPayloadLen = un;

                            if (!s->isDirect) {
                                if (!ParseSocks5UdpPacket(respBuf, un, respPayload, respPayloadLen)) {
                                    continue;
                                }
                            }

                            // 包装为 SOCKS5 UDP 应答发回客户端
                            auto clientPacket = BuildSocks5UdpPacket(targetHost, targetPort, respPayload, respPayloadLen);
                            sendto(s->socksClientUdpSock, clientPacket.data(), clientPacket.size(), 0,
                                   (sockaddr*)&s->clientAddr, sizeof(s->clientAddr));

                            TrafficMonitor::Instance().RecordDownload(s->userId, s->portId, respPayloadLen);
                            RealtimeConnectionManager::Instance().RecordTraffic(s->connId, 0, respPayloadLen);
                        }
                    } catch (const std::exception& e) {
                        std::cerr << "[UdpRelay] Exception in socks workerThread: " << e.what() << std::endl;
                    } catch (...) {
                        std::cerr << "[UdpRelay] Unknown exception in socks workerThread" << std::endl;
                    }

                    RealtimeConnectionManager::Instance().CloseConnection(s->connId);
                    s->running.store(false);
                });
                s->workerThread.detach();
            }

            s->lastActive = std::chrono::steady_clock::now();
            s->clientAddr = clientUdpEndpoint;

            // 发送数据包至上游节点或目标服务器
            if (s->isDirect) {
                sockaddr_in destAddr{};
                destAddr.sin_family = AF_INET;
                destAddr.sin_port = htons(targetPort);
                inet_pton(AF_INET, targetIP.c_str(), &destAddr.sin_addr);
                sendto(s->upstreamSock, payload, payloadLen, 0, (sockaddr*)&destAddr, sizeof(destAddr));
            } else {
                auto upPacket = BuildSocks5UdpPacket(targetHost, targetPort, payload, payloadLen);
                sendto(s->upstreamSock, upPacket.data(), upPacket.size(), 0,
                       (sockaddr*)&s->upstreamRelayAddr, sizeof(s->upstreamRelayAddr));
            }

            TrafficMonitor::Instance().RecordUpload(userId, s->portId, payloadLen);
            RealtimeConnectionManager::Instance().RecordTraffic(s->connId, payloadLen, 0);
        }
    }

    // 清理 SOCKS5 UDP 关联资源
    for (auto& pair : socksSessions) {
        pair.second->running.store(false);
        if (pair.second->upstreamSock != INVALID_SOCKET) {
            closesocket(pair.second->upstreamSock);
            pair.second->upstreamSock = INVALID_SOCKET;
        }
        if (pair.second->tcpControlSock != INVALID_SOCKET) {
            closesocket(pair.second->tcpControlSock);
            pair.second->tcpControlSock = INVALID_SOCKET;
        }
        if (pair.second->workerThread.joinable()) {
            pair.second->workerThread.detach();
        }
    }
    if (socksClientUdpSock != INVALID_SOCKET) {
        closesocket(socksClientUdpSock);
    }
    closesocket(clientTcpSock);
}

void UdpRelayManager::ScavengerThread() {
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(15));
        if (!running_.load()) break;

        auto now = std::chrono::steady_clock::now();
        std::vector<std::string> toRemove;

        {
            std::lock_guard<std::mutex> lock(sessionsMutex_);
            for (auto& pair : sessions_) {
                auto& s = pair.second;
                int idleSec = std::chrono::duration_cast<std::chrono::seconds>(now - s->lastActive).count();
                if (idleSec > 60 || !s->running.load()) {
                    s->running.store(false);
                    toRemove.push_back(pair.first);
                }
            }

            for (const auto& key : toRemove) {
                auto it = sessions_.find(key);
                if (it != sessions_.end()) {
                    auto& s = it->second;
                    RealtimeConnectionManager::Instance().CloseConnection(s->connId);
                    if (s->upstreamSock != INVALID_SOCKET) {
                        closesocket(s->upstreamSock);
                        s->upstreamSock = INVALID_SOCKET;
                    }
                    if (s->tcpControlSock != INVALID_SOCKET) {
                        closesocket(s->tcpControlSock);
                        s->tcpControlSock = INVALID_SOCKET;
                    }
                    if (s->spoofSock != INVALID_SOCKET) {
                        closesocket(s->spoofSock);
                        s->spoofSock = INVALID_SOCKET;
                    }
                    if (s->workerThread.joinable()) {
                        s->workerThread.detach();
                    }
                    sessions_.erase(it);
                }
            }
        }
    }
}
