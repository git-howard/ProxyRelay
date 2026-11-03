#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <string>
#include <map>
#include <mutex>
#include <vector>

// Xray 协议配置
struct XrayConfig {
    // 基本连接信息
    std::string protocol;       // vless, vmess, trojan, shadowsocks
    std::string address;        // 远程服务器地址
    int port = 443;             // 远程服务器端口
    
    // 认证信息
    std::string uuid;           // VLESS/VMess UUID
    std::string password;       // Trojan 密码 / Shadowsocks 密码
    std::string encryption;     // VMess 加密方式 / Shadowsocks 加密方式
    std::string flow;           // VLESS flow (xtls-rprx-vision 等)
    int alterId = 0;            // VMess alterId
    
    // 传输层配置
    std::string network;        // tcp, ws, grpc, h2, quic, kcp
    std::string security;       // tls, reality, none
    std::string headerType;     // 伪装头部类型 (none, http 等)
    std::string sni;            // TLS SNI
    std::string fingerprint;    // TLS 指纹 (chrome, firefox, safari, etc.)
    bool allowInsecure = false; // 跳过证书验证
    std::string alpn;           // ALPN (h2,http/1.1)
    
    // WebSocket 配置
    std::string wsPath;         // WebSocket 路径
    std::string wsHost;         // WebSocket Host
    
    // gRPC 配置
    std::string grpcServiceName;
    
    // REALITY 配置
    std::string realityPublicKey;
    std::string realityShortId;
    std::string realitySpiderX;
    
    // 原始 JSON 配置（优先使用，如非空则忽略上面的字段）
    std::string rawJson;
    
    // 本地 SOCKS5 端口（自动分配）
    int localSocksPort = 0;
};

class XrayManager {
public:
    static XrayManager& Instance();
    
    // 初始化（查找 xray.exe 路径）
    bool Initialize();
    
    // 为指定代理端口启动 xray 进程
    // portId: 代理端口 ID
    // config: xray 配置
    // 返回本地 SOCKS5 端口号，失败返回 0
    int StartXray(int portId, const XrayConfig& config);
    
    // 获取所有运行中的 xray 子进程 PID
    std::vector<DWORD> GetAllProcessIds();
    
    // 停止指定代理端口的 xray 进程
    void StopXray(int portId);
    
    // 停止所有 xray 进程
    void StopAll();
    
    // 获取指定端口的本地 SOCKS5 端口
    int GetLocalSocksPort(int portId);
    
    // 检查 xray 是否正在运行
    bool IsRunning(int portId);
    
    // 检查 xray-core 是否可用
    bool IsXrayAvailable() const { return !xrayPath_.empty(); }
    std::string GetXrayPath() const { return xrayPath_; }
    
    // 解析 xray 配置 JSON 字符串
    static XrayConfig ParseConfigJson(const std::string& json);
    
    // 将 XrayConfig 序列化为存储用 JSON
    static std::string SerializeConfig(const XrayConfig& config);
    
    // 生成 xray-core 的完整配置 JSON 文件
    std::string GenerateXrayConfigFile(const XrayConfig& config, int localSocksPort);
    
    // 解析分享链接 (vmess://, vless://, trojan://, ss://)
    // 返回解析后的 XrayConfig，解析失败时 protocol 为空
    static XrayConfig ParseShareLink(const std::string& link);
    
    // 从分享链接中提取描述名
    static std::string ExtractNameFromLink(const std::string& link);
    
private:
    XrayManager() = default;
    ~XrayManager();
    
    // 查找可用的本地端口
    int FindAvailablePort();
    
    // xray 进程信息
    struct XrayProcess {
        HANDLE hProcess = nullptr;
        HANDLE hThread = nullptr;
        DWORD processId = 0;           // 子进程 PID，用于全局代理排除
        int localSocksPort = 0;
        std::string configPath;
    };
    
    std::string xrayPath_;
    std::mutex mutex_;
    std::map<int, XrayProcess> processes_;
    
    // 端口分配范围
    static const int PORT_RANGE_START = 20000;
    static const int PORT_RANGE_END = 30000;
    int nextPort_ = PORT_RANGE_START;
};
