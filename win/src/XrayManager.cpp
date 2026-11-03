#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "XrayManager.h"
#include "Utils.h"
#include <sstream>
#include <fstream>
#include <filesystem>
#include <map>

XrayManager& XrayManager::Instance() {
    static XrayManager instance;
    return instance;
}

XrayManager::~XrayManager() {
    StopAll();
}

bool XrayManager::Initialize() {
    char exePath[MAX_PATH];
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    std::string exeDir = std::filesystem::path(exePath).parent_path().string();
    
    std::string xrayPath = exeDir + "\\xray.exe";
    if (std::filesystem::exists(xrayPath)) {
        xrayPath_ = xrayPath;
        Utils::Log("Xray found: " + xrayPath_);
        return true;
    }
    
    std::string xrayPathParent = exeDir + "\\..\\xray.exe";
    if (std::filesystem::exists(xrayPathParent)) {
        xrayPath_ = std::filesystem::canonical(xrayPathParent).string();
        Utils::Log("Xray found: " + xrayPath_);
        return true;
    }
    
    xrayPath = "xray.exe";
    if (std::filesystem::exists(xrayPath)) {
        xrayPath_ = std::filesystem::absolute(xrayPath).string();
        Utils::Log("Xray found: " + xrayPath_);
        return true;
    }
    
    // 如果找不到 xray.exe，但存在 Xray-windows-64.zip，尝试自动解压
    std::string zipPath1 = exeDir + "\\Xray-windows-64.zip";
    std::string zipPath2 = "Xray-windows-64.zip";
    std::string targetZip = std::filesystem::exists(zipPath1) ? zipPath1 : (std::filesystem::exists(zipPath2) ? zipPath2 : "");
    if (!targetZip.empty()) {
        Utils::Log("xray.exe not found, attempting to extract from " + targetZip + "...");
        std::string cmd = "powershell -Command \"Expand-Archive -Path '" + targetZip + "' -DestinationPath '" + exeDir + "' -Force\"";
        system(cmd.c_str());
        if (std::filesystem::exists(xrayPath)) {
            xrayPath_ = std::filesystem::absolute(xrayPath).string();
            Utils::Log("Xray successfully extracted: " + xrayPath_);
            return true;
        }
    }
    
    Utils::Log("Xray not found, xray upstream will not be available");
    return false;
}

static HANDLE GetXrayJobObject() {
    static HANDLE s_hJob = nullptr;
    static std::once_flag s_jobFlag;
    std::call_once(s_jobFlag, []() {
        s_hJob = CreateJobObjectW(nullptr, nullptr);
        if (s_hJob) {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {};
            jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(s_hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
        }
    });
    return s_hJob;
}

int XrayManager::StartXray(int portId, const XrayConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // 如果已在运行，先停止
    auto it = processes_.find(portId);
    if (it != processes_.end()) {
        if (it->second.hProcess) {
            TerminateProcess(it->second.hProcess, 0);
            CloseHandle(it->second.hProcess);
            CloseHandle(it->second.hThread);
        }
        if (!it->second.configPath.empty()) {
            std::filesystem::remove(it->second.configPath);
        }
        processes_.erase(it);
    }
    
    if (xrayPath_.empty()) {
        Utils::LogError("Xray not available");
        return 0;
    }
    
    // 分配本地 SOCKS5 端口
    int localPort = FindAvailablePort();
    if (localPort == 0) {
        Utils::LogError("Failed to find available port for xray");
        return 0;
    }
    
    // 生成配置文件
    std::string configContent = GenerateXrayConfigFile(config, localPort);
    
    // 确保 data 目录存在
    std::filesystem::create_directories("data");
    std::string configPath = "data/xray_" + std::to_string(portId) + ".json";
    
    std::ofstream configFile(configPath);
    if (!configFile.is_open()) {
        Utils::LogError("Failed to write xray config file: " + configPath);
        return 0;
    }
    configFile << configContent;
    configFile.close();
    
    // 启动 xray 进程
    std::string cmdLine = "\"" + xrayPath_ + "\" run -c \"" + 
                           std::filesystem::absolute(configPath).string() + "\"";
    
    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // 隐藏窗口
    
    PROCESS_INFORMATION pi = {};
    
    if (!CreateProcessA(
        nullptr,
        const_cast<char*>(cmdLine.c_str()),
        nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW | DETACHED_PROCESS,
        nullptr, nullptr,
        &si, &pi)) {
        Utils::LogError("Failed to start xray process, error: " + std::to_string(GetLastError()));
        std::filesystem::remove(configPath);
        return 0;
    }
    
    HANDLE hJob = GetXrayJobObject();
    if (hJob) {
        AssignProcessToJobObject(hJob, pi.hProcess);
    }
    
    // 等待短暂时间让 xray 启动（最多100ms，进程若异常退出则立即检测到）
    DWORD waitResult = WaitForSingleObject(pi.hProcess, 100);
    if (waitResult == WAIT_OBJECT_0) {
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        Utils::LogError("Xray process exited immediately with code: " + std::to_string(exitCode));
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        std::filesystem::remove(configPath);
        return 0;
    }
    
    XrayProcess proc;
    proc.hProcess = pi.hProcess;
    proc.hThread = pi.hThread;
    proc.processId = pi.dwProcessId;
    proc.localSocksPort = localPort;
    proc.configPath = configPath;
    
    processes_[portId] = proc;
    
    Utils::Log("Xray started for port " + std::to_string(portId) + 
               ", local SOCKS5 port: " + std::to_string(localPort) +
               ", PID: " + std::to_string(pi.dwProcessId));
    
    return localPort;
}

void XrayManager::StopXray(int portId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = processes_.find(portId);
    if (it == processes_.end()) return;
    
    auto& proc = it->second;
    if (proc.hProcess) {
        TerminateProcess(proc.hProcess, 0);
        WaitForSingleObject(proc.hProcess, 3000);
        CloseHandle(proc.hProcess);
        CloseHandle(proc.hThread);
    }
    
    if (!proc.configPath.empty()) {
        try { std::filesystem::remove(proc.configPath); } catch (...) {}
    }
    
    Utils::Log("Xray stopped for port " + std::to_string(portId));
    processes_.erase(it);
}

void XrayManager::StopAll() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto& pair : processes_) {
        auto& proc = pair.second;
        if (proc.hProcess) {
            TerminateProcess(proc.hProcess, 0);
            WaitForSingleObject(proc.hProcess, 3000);
            CloseHandle(proc.hProcess);
            CloseHandle(proc.hThread);
        }
        if (!proc.configPath.empty()) {
            try { std::filesystem::remove(proc.configPath); } catch (...) {}
        }
    }
    processes_.clear();
    Utils::Log("All xray processes stopped");
}

int XrayManager::GetLocalSocksPort(int portId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = processes_.find(portId);
    if (it == processes_.end()) return 0;
    return it->second.localSocksPort;
}

bool XrayManager::IsRunning(int portId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = processes_.find(portId);
    if (it == processes_.end()) return false;
    
    if (!it->second.hProcess) return false;
    
    DWORD exitCode;
    if (GetExitCodeProcess(it->second.hProcess, &exitCode)) {
        return exitCode == STILL_ACTIVE;
    }
    return false;
}

int XrayManager::FindAvailablePort() {
    for (int attempt = 0; attempt < (PORT_RANGE_END - PORT_RANGE_START); attempt++) {
        int port = nextPort_++;
        if (nextPort_ >= PORT_RANGE_END) nextPort_ = PORT_RANGE_START;
        
        // 检查端口是否被已分配的 xray 进程使用
        bool inUse = false;
        for (const auto& pair : processes_) {
            if (pair.second.localSocksPort == port) {
                inUse = true;
                break;
            }
        }
        if (inUse) continue;
        
        // 尝试绑定端口来检查是否可用
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) continue;
        
        sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port);
        
        if (bind(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
            closesocket(sock);
            return port;
        }
        closesocket(sock);
    }
    return 0;
}

// 简单的 JSON 字符串转义
static std::string JsonEscape(const std::string& s) {
    std::string result;
    for (char c : s) {
        switch (c) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default: result += c;
        }
    }
    return result;
}

std::string XrayManager::GenerateXrayConfigFile(const XrayConfig& config, int localSocksPort) {
    // 如果提供了原始 JSON，使用原始配置但注入本地 inbound
    if (!config.rawJson.empty()) {
        // 尝试在原始 JSON 中找到 inbounds 并修改端口
        // 为简单起见，生成一个包装配置
        // 用户提供的是 outbound 配置，我们添加 inbound
        std::ostringstream oss;
        oss << "{\n";
        oss << "  \"log\": { \"loglevel\": \"warning\" },\n";
        oss << "  \"inbounds\": [{\n";
        oss << "    \"port\": " << localSocksPort << ",\n";
        oss << "    \"listen\": \"127.0.0.1\",\n";
        oss << "    \"protocol\": \"socks\",\n";
        oss << "    \"settings\": { \"auth\": \"noauth\", \"udp\": true }\n";
        oss << "  }],\n";
        oss << "  \"outbounds\": [" << config.rawJson << "]\n";
        oss << "}\n";
        return oss.str();
    }
    
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"log\": { \"loglevel\": \"warning\" },\n";
    
    // Inbound: 本地 SOCKS5
    oss << "  \"inbounds\": [{\n";
    oss << "    \"port\": " << localSocksPort << ",\n";
    oss << "    \"listen\": \"127.0.0.1\",\n";
    oss << "    \"protocol\": \"socks\",\n";
    oss << "    \"settings\": { \"auth\": \"noauth\", \"udp\": true }\n";
    oss << "  }],\n";
    
    // Outbound
    oss << "  \"outbounds\": [{\n";
    oss << "    \"protocol\": \"" << JsonEscape(config.protocol) << "\",\n";
    oss << "    \"settings\": {\n";
    
    if (config.protocol == "vless") {
        oss << "      \"vnext\": [{\n";
        oss << "        \"address\": \"" << JsonEscape(config.address) << "\",\n";
        oss << "        \"port\": " << config.port << ",\n";
        oss << "        \"users\": [{\n";
        oss << "          \"id\": \"" << JsonEscape(config.uuid) << "\",\n";
        oss << "          \"encryption\": \"none\"";
        if (!config.flow.empty()) {
            oss << ",\n          \"flow\": \"" << JsonEscape(config.flow) << "\"";
        }
        oss << "\n        }]\n";
        oss << "      }]\n";
    } else if (config.protocol == "vmess") {
        oss << "      \"vnext\": [{\n";
        oss << "        \"address\": \"" << JsonEscape(config.address) << "\",\n";
        oss << "        \"port\": " << config.port << ",\n";
        oss << "        \"users\": [{\n";
        oss << "          \"id\": \"" << JsonEscape(config.uuid) << "\",\n";
        oss << "          \"alterId\": " << config.alterId << ",\n";
        oss << "          \"security\": \"" << JsonEscape(config.encryption.empty() ? "auto" : config.encryption) << "\"\n";
        oss << "        }]\n";
        oss << "      }]\n";
    } else if (config.protocol == "trojan") {
        oss << "      \"servers\": [{\n";
        oss << "        \"address\": \"" << JsonEscape(config.address) << "\",\n";
        oss << "        \"port\": " << config.port << ",\n";
        oss << "        \"password\": \"" << JsonEscape(config.password) << "\"\n";
        oss << "      }]\n";
    } else if (config.protocol == "shadowsocks") {
        oss << "      \"servers\": [{\n";
        oss << "        \"address\": \"" << JsonEscape(config.address) << "\",\n";
        oss << "        \"port\": " << config.port << ",\n";
        oss << "        \"method\": \"" << JsonEscape(config.encryption.empty() ? "aes-256-gcm" : config.encryption) << "\",\n";
        oss << "        \"password\": \"" << JsonEscape(config.password) << "\"\n";
        oss << "      }]\n";
    }
    
    oss << "    },\n";
    
    // 传输层设置（StreamSettings）
    oss << "    \"streamSettings\": {\n";
    oss << "      \"network\": \"" << JsonEscape(config.network.empty() ? "tcp" : config.network) << "\"";
    
    // TLS / REALITY 设置
    std::string security = config.security;
    if (security.empty()) {
        // 默认: Trojan 使用 tls，其他看情况
        if (config.protocol == "trojan") security = "tls";
        else security = "none";
    }
    oss << ",\n      \"security\": \"" << JsonEscape(security) << "\"";
    
    if (security == "tls") {
        oss << ",\n      \"tlsSettings\": {\n";
        if (!config.sni.empty()) {
            oss << "        \"serverName\": \"" << JsonEscape(config.sni) << "\",\n";
        }
        if (!config.fingerprint.empty()) {
            oss << "        \"fingerprint\": \"" << JsonEscape(config.fingerprint) << "\",\n";
        }
        if (!config.alpn.empty()) {
            oss << "        \"alpn\": [";
            // 解析逗号分隔的 ALPN
            std::istringstream alpnStream(config.alpn);
            std::string alpnItem;
            bool first = true;
            while (std::getline(alpnStream, alpnItem, ',')) {
                if (!first) oss << ", ";
                // 去除空格
                size_t start = alpnItem.find_first_not_of(' ');
                size_t end = alpnItem.find_last_not_of(' ');
                if (start != std::string::npos) {
                    oss << "\"" << JsonEscape(alpnItem.substr(start, end - start + 1)) << "\"";
                }
                first = false;
            }
            oss << "],\n";
        }
        oss << "        \"allowInsecure\": " << (config.allowInsecure ? "true" : "false") << "\n";
        oss << "      }";
    } else if (security == "reality") {
        oss << ",\n      \"realitySettings\": {\n";
        if (!config.sni.empty()) {
            oss << "        \"serverName\": \"" << JsonEscape(config.sni) << "\",\n";
        }
        if (!config.fingerprint.empty()) {
            oss << "        \"fingerprint\": \"" << JsonEscape(config.fingerprint) << "\",\n";
        }
        if (!config.realityPublicKey.empty()) {
            oss << "        \"publicKey\": \"" << JsonEscape(config.realityPublicKey) << "\",\n";
        }
        if (!config.realityShortId.empty()) {
            oss << "        \"shortId\": \"" << JsonEscape(config.realityShortId) << "\",\n";
        }
        if (!config.realitySpiderX.empty()) {
            oss << "        \"spiderX\": \"" << JsonEscape(config.realitySpiderX) << "\",\n";
        }
        oss << "        \"show\": false\n";
        oss << "      }";
    }
    
    // WebSocket 设置
    if (config.network == "ws") {
        oss << ",\n      \"wsSettings\": {\n";
        oss << "        \"path\": \"" << JsonEscape(config.wsPath.empty() ? "/" : config.wsPath) << "\"";
        if (!config.wsHost.empty()) {
            oss << ",\n        \"headers\": { \"Host\": \"" << JsonEscape(config.wsHost) << "\" }";
        }
        oss << "\n      }";
    }
    
    // TCP HTTP 伪装设置
    if (config.network == "tcp" && !config.headerType.empty() && config.headerType != "none") {
        oss << ",\n      \"tcpSettings\": {\n";
        oss << "        \"header\": {\n";
        oss << "          \"type\": \"" << JsonEscape(config.headerType) << "\"";
        
        if (config.headerType == "http" && (!config.wsHost.empty() || !config.wsPath.empty())) {
            oss << ",\n          \"request\": {\n";
            bool hasPath = false;
            
            // Xray 要求 path 是数组
            if (!config.wsPath.empty()) {
                oss << "            \"path\": [\"" << JsonEscape(config.wsPath) << "\"]";
                hasPath = true;
            } else {
                oss << "            \"path\": [\"/\"]";
                hasPath = true;
            }
            
            if (!config.wsHost.empty()) {
                if (hasPath) oss << ",\n";
                // Xray 要求 headers.Host 是数组
                oss << "            \"headers\": {\n";
                oss << "              \"Host\": [\"" << JsonEscape(config.wsHost) << "\"]\n";
                oss << "            }";
            }
            oss << "\n          }";
        }
        oss << "\n        }\n";
        oss << "      }";
    }
    
    // gRPC 设置
    if (config.network == "grpc") {
        oss << ",\n      \"grpcSettings\": {\n";
        oss << "        \"serviceName\": \"" << JsonEscape(config.grpcServiceName) << "\"\n";
        oss << "      }";
    }
    
    oss << "\n    }\n";  // 结束 streamSettings
    oss << "  }]\n";     // 结束 outbounds
    oss << "}\n";
    
    return oss.str();
}

// 将 XrayConfig 序列化为简单的键值对存储格式
std::string XrayManager::SerializeConfig(const XrayConfig& config) {
    std::ostringstream oss;
    // 使用简单的 JSON 格式存储
    oss << "{";
    oss << "\"protocol\":\"" << JsonEscape(config.protocol) << "\",";
    oss << "\"address\":\"" << JsonEscape(config.address) << "\",";
    oss << "\"port\":" << config.port << ",";
    oss << "\"uuid\":\"" << JsonEscape(config.uuid) << "\",";
    oss << "\"password\":\"" << JsonEscape(config.password) << "\",";
    oss << "\"encryption\":\"" << JsonEscape(config.encryption) << "\",";
    oss << "\"flow\":\"" << JsonEscape(config.flow) << "\",";
    oss << "\"alterId\":" << config.alterId << ",";
    oss << "\"network\":\"" << JsonEscape(config.network) << "\",";
    oss << "\"security\":\"" << JsonEscape(config.security) << "\",";
    oss << "\"headerType\":\"" << JsonEscape(config.headerType) << "\",";
    oss << "\"sni\":\"" << JsonEscape(config.sni) << "\",";
    oss << "\"fingerprint\":\"" << JsonEscape(config.fingerprint) << "\",";
    oss << "\"allowInsecure\":" << (config.allowInsecure ? "true" : "false") << ",";
    oss << "\"alpn\":\"" << JsonEscape(config.alpn) << "\",";
    oss << "\"wsPath\":\"" << JsonEscape(config.wsPath) << "\",";
    oss << "\"wsHost\":\"" << JsonEscape(config.wsHost) << "\",";
    oss << "\"grpcServiceName\":\"" << JsonEscape(config.grpcServiceName) << "\",";
    oss << "\"realityPublicKey\":\"" << JsonEscape(config.realityPublicKey) << "\",";
    oss << "\"realityShortId\":\"" << JsonEscape(config.realityShortId) << "\",";
    oss << "\"realitySpiderX\":\"" << JsonEscape(config.realitySpiderX) << "\",";
    oss << "\"rawJson\":\"" << JsonEscape(config.rawJson) << "\"";
    oss << "}";
    return oss.str();
}

// 简易 JSON 值提取（不依赖第三方库）
// 兼容 "key":"value" 和 "key": "value" 两种格式
static std::string ExtractJsonString(const std::string& json, const std::string& key) {
    std::string searchKey = "\"" + key + "\"";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) return "";
    pos += searchKey.length();
    
    // 跳过空白
    while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n'))
        pos++;
    
    // 期望冒号
    if (pos >= json.length() || json[pos] != ':') return "";
    pos++;
    
    // 跳过空白
    while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n'))
        pos++;
    
    // 期望引号
    if (pos >= json.length() || json[pos] != '"') return "";
    pos++;
    
    std::string result;
    while (pos < json.length() && json[pos] != '"') {
        if (json[pos] == '\\' && pos + 1 < json.length()) {
            pos++;
            switch (json[pos]) {
                case '"': result += '"'; break;
                case '\\': result += '\\'; break;
                case 'n': result += '\n'; break;
                case 'r': result += '\r'; break;
                case 't': result += '\t'; break;
                default: result += json[pos]; break;
            }
        } else {
            result += json[pos];
        }
        pos++;
    }
    return result;
}

static int ExtractJsonInt(const std::string& json, const std::string& key) {
    std::string searchKey = "\"" + key + "\"";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) return 0;
    pos += searchKey.length();
    
    // 跳过空白和冒号
    while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n'))
        pos++;
    if (pos >= json.length() || json[pos] != ':') return 0;
    pos++;
    while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n'))
        pos++;
    
    std::string numStr;
    while (pos < json.length() && (json[pos] == '-' || isdigit(json[pos]))) {
        numStr += json[pos++];
    }
    return numStr.empty() ? 0 : std::atoi(numStr.c_str());
}

static bool ExtractJsonBool(const std::string& json, const std::string& key) {
    std::string searchKey = "\"" + key + "\"";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) return false;
    pos += searchKey.length();
    
    // 跳过空白和冒号
    while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n'))
        pos++;
    if (pos >= json.length() || json[pos] != ':') return false;
    pos++;
    while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n'))
        pos++;
    
    return json.substr(pos, 4) == "true";
}

XrayConfig XrayManager::ParseConfigJson(const std::string& json) {
    XrayConfig config;
    config.protocol = ExtractJsonString(json, "protocol");
    config.address = ExtractJsonString(json, "address");
    config.port = ExtractJsonInt(json, "port");
    if (config.port == 0) config.port = 443;
    config.uuid = ExtractJsonString(json, "uuid");
    config.password = ExtractJsonString(json, "password");
    config.encryption = ExtractJsonString(json, "encryption");
    config.flow = ExtractJsonString(json, "flow");
    config.alterId = ExtractJsonInt(json, "alterId");
    config.network = ExtractJsonString(json, "network");
    config.security = ExtractJsonString(json, "security");
    config.headerType = ExtractJsonString(json, "headerType");
    config.sni = ExtractJsonString(json, "sni");
    config.fingerprint = ExtractJsonString(json, "fingerprint");
    config.allowInsecure = ExtractJsonBool(json, "allowInsecure");
    config.alpn = ExtractJsonString(json, "alpn");
    config.wsPath = ExtractJsonString(json, "wsPath");
    config.wsHost = ExtractJsonString(json, "wsHost");
    config.grpcServiceName = ExtractJsonString(json, "grpcServiceName");
    config.realityPublicKey = ExtractJsonString(json, "realityPublicKey");
    config.realityShortId = ExtractJsonString(json, "realityShortId");
    config.realitySpiderX = ExtractJsonString(json, "realitySpiderX");
    config.rawJson = ExtractJsonString(json, "rawJson");
    return config;
}

// ============================
// 分享链接解析
// ============================

// Base64 解码
static std::string Base64Decode(const std::string& encoded) {
    static const std::string chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    // 处理 URL-safe Base64: 将 - 替换为 +, _ 替换为 /
    std::string input = encoded;
    for (auto& c : input) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    
    // 去除尾部空白和换行
    while (!input.empty() && (input.back() == '\n' || input.back() == '\r' || input.back() == ' '))
        input.pop_back();
    
    // 补齐 padding
    while (input.length() % 4 != 0) input += '=';
    
    std::string result;
    int val = 0, bits = -8;
    for (char c : input) {
        if (c == '=') break;
        size_t pos = chars.find(c);
        if (pos == std::string::npos) continue;
        val = (val << 6) + (int)pos;
        bits += 6;
        if (bits >= 0) {
            result += char((val >> bits) & 0xFF);
            bits -= 8;
        }
    }
    return result;
}

// URL 解码
static std::string UrlDecode(const std::string& str) {
    std::string result;
    for (size_t i = 0; i < str.length(); i++) {
        if (str[i] == '%' && i + 2 < str.length()) {
            int hex;
            std::istringstream iss(str.substr(i + 1, 2));
            if (iss >> std::hex >> hex) {
                result += (char)hex;
                i += 2;
            } else {
                result += str[i];
            }
        } else if (str[i] == '+') {
            result += ' ';
        } else {
            result += str[i];
        }
    }
    return result;
}

// 解析 URI query 参数
static std::map<std::string, std::string> ParseQueryParams(const std::string& query) {
    std::map<std::string, std::string> params;
    std::istringstream iss(query);
    std::string pair;
    while (std::getline(iss, pair, '&')) {
        size_t eq = pair.find('=');
        if (eq != std::string::npos) {
            params[pair.substr(0, eq)] = UrlDecode(pair.substr(eq + 1));
        }
    }
    return params;
}

// 解析 vmess:// 链接
static XrayConfig ParseVmessLink(const std::string& data) {
    XrayConfig config;
    
    std::string decoded = Base64Decode(data);
    if (decoded.empty()) return config;
    
    // vmess JSON 格式:
    // { "v":"2", "ps":"name", "add":"addr", "port":"port", "id":"uuid",
    //   "aid":"0", "scy":"auto", "net":"tcp", "type":"none",
    //   "host":"", "path":"", "tls":"", "sni":"", "alpn":"", "fp":"" }
    
    config.protocol = "vmess";
    config.address = ExtractJsonString(decoded, "add");
    
    // port 可能是字符串或数字
    std::string portStr = ExtractJsonString(decoded, "port");
    if (!portStr.empty()) {
        config.port = std::atoi(portStr.c_str());
    } else {
        config.port = ExtractJsonInt(decoded, "port");
    }
    if (config.port <= 0) config.port = 443;
    
    config.uuid = ExtractJsonString(decoded, "id");
    
    std::string aidStr = ExtractJsonString(decoded, "aid");
    if (!aidStr.empty()) {
        config.alterId = std::atoi(aidStr.c_str());
    } else {
        config.alterId = ExtractJsonInt(decoded, "aid");
    }
    
    config.encryption = ExtractJsonString(decoded, "scy");
    if (config.encryption.empty()) config.encryption = "auto";
    
    config.network = ExtractJsonString(decoded, "net");
    if (config.network.empty()) config.network = "tcp";
    
    config.headerType = ExtractJsonString(decoded, "type");
    
    // TLS
    std::string tls = ExtractJsonString(decoded, "tls");
    if (tls == "tls") {
        config.security = "tls";
    } else {
        config.security = "none";
    }
    
    config.sni = ExtractJsonString(decoded, "sni");
    config.alpn = ExtractJsonString(decoded, "alpn");
    config.fingerprint = ExtractJsonString(decoded, "fp");
    
    // 传输层参数
    config.wsHost = ExtractJsonString(decoded, "host");
    config.wsPath = ExtractJsonString(decoded, "path");
    
    // gRPC 时，path 作为 serviceName
    if (config.network == "grpc") {
        config.grpcServiceName = config.wsPath;
    }
    
    return config;
}

// 解析 vless:// 链接
// 格式: vless://uuid@host:port?params#name
static XrayConfig ParseVlessLink(const std::string& data) {
    XrayConfig config;
    config.protocol = "vless";
    
    // 先分离 #name
    std::string body = data;
    size_t hashPos = body.find('#');
    if (hashPos != std::string::npos) {
        body = body.substr(0, hashPos);
    }
    
    // 分离 ?params
    std::string params;
    size_t qPos = body.find('?');
    if (qPos != std::string::npos) {
        params = body.substr(qPos + 1);
        body = body.substr(0, qPos);
    }
    
    // 解析 uuid@host:port
    size_t atPos = body.find('@');
    if (atPos == std::string::npos) return XrayConfig(); // 解析失败
    
    config.uuid = body.substr(0, atPos);
    std::string hostPort = body.substr(atPos + 1);
    
    // 处理 IPv6: [::1]:port
    size_t colonPos;
    if (hostPort[0] == '[') {
        size_t bracketEnd = hostPort.find(']');
        if (bracketEnd != std::string::npos) {
            config.address = hostPort.substr(1, bracketEnd - 1);
            if (bracketEnd + 1 < hostPort.length() && hostPort[bracketEnd + 1] == ':') {
                config.port = std::atoi(hostPort.substr(bracketEnd + 2).c_str());
            }
        }
    } else {
        colonPos = hostPort.rfind(':');
        if (colonPos != std::string::npos) {
            config.address = hostPort.substr(0, colonPos);
            config.port = std::atoi(hostPort.substr(colonPos + 1).c_str());
        } else {
            config.address = hostPort;
        }
    }
    if (config.port <= 0) config.port = 443;
    
    // 解析查询参数
    auto qp = ParseQueryParams(params);
    
    config.encryption = qp.count("encryption") ? qp["encryption"] : "none";
    config.flow = qp.count("flow") ? qp["flow"] : "";
    config.network = qp.count("type") ? qp["type"] : "tcp";
    config.security = qp.count("security") ? qp["security"] : "none";
    config.headerType = qp.count("headerType") ? qp["headerType"] : "";
    config.sni = qp.count("sni") ? qp["sni"] : "";
    config.fingerprint = qp.count("fp") ? qp["fp"] : "";
    config.alpn = qp.count("alpn") ? qp["alpn"] : "";
    config.wsPath = qp.count("path") ? qp["path"] : "";
    config.wsHost = qp.count("host") ? qp["host"] : "";
    config.grpcServiceName = qp.count("serviceName") ? qp["serviceName"] : "";
    config.realityPublicKey = qp.count("pbk") ? qp["pbk"] : "";
    config.realityShortId = qp.count("sid") ? qp["sid"] : "";
    config.realitySpiderX = qp.count("spx") ? qp["spx"] : "";
    config.allowInsecure = (qp.count("allowInsecure") && qp["allowInsecure"] == "1");
    
    return config;
}

// 解析 trojan:// 链接
// 格式: trojan://password@host:port?params#name
static XrayConfig ParseTrojanLink(const std::string& data) {
    XrayConfig config;
    config.protocol = "trojan";
    
    // 先分离 #name
    std::string body = data;
    size_t hashPos = body.find('#');
    if (hashPos != std::string::npos) {
        body = body.substr(0, hashPos);
    }
    
    // 分离 ?params
    std::string params;
    size_t qPos = body.find('?');
    if (qPos != std::string::npos) {
        params = body.substr(qPos + 1);
        body = body.substr(0, qPos);
    }
    
    // 解析 password@host:port
    size_t atPos = body.find('@');
    if (atPos == std::string::npos) return XrayConfig();
    
    config.password = UrlDecode(body.substr(0, atPos));
    std::string hostPort = body.substr(atPos + 1);
    
    // 处理 IPv6
    if (hostPort[0] == '[') {
        size_t bracketEnd = hostPort.find(']');
        if (bracketEnd != std::string::npos) {
            config.address = hostPort.substr(1, bracketEnd - 1);
            if (bracketEnd + 1 < hostPort.length() && hostPort[bracketEnd + 1] == ':') {
                config.port = std::atoi(hostPort.substr(bracketEnd + 2).c_str());
            }
        }
    } else {
        size_t colonPos = hostPort.rfind(':');
        if (colonPos != std::string::npos) {
            config.address = hostPort.substr(0, colonPos);
            config.port = std::atoi(hostPort.substr(colonPos + 1).c_str());
        } else {
            config.address = hostPort;
        }
    }
    if (config.port <= 0) config.port = 443;
    
    // 默认 tls
    config.security = "tls";
    
    // 解析查询参数
    auto qp = ParseQueryParams(params);
    
    if (qp.count("security")) config.security = qp["security"];
    config.network = qp.count("type") ? qp["type"] : "tcp";
    config.headerType = qp.count("headerType") ? qp["headerType"] : "";
    config.sni = qp.count("sni") ? qp["sni"] : "";
    config.fingerprint = qp.count("fp") ? qp["fp"] : "";
    config.alpn = qp.count("alpn") ? qp["alpn"] : "";
    config.wsPath = qp.count("path") ? qp["path"] : "";
    config.wsHost = qp.count("host") ? qp["host"] : "";
    config.grpcServiceName = qp.count("serviceName") ? qp["serviceName"] : "";
    config.allowInsecure = (qp.count("allowInsecure") && qp["allowInsecure"] == "1");
    
    return config;
}

// 解析 ss:// 链接
// SIP002 格式: ss://base64(method:password)@host:port#name
// 旧格式: ss://base64(method:password@host:port)#name
static XrayConfig ParseShadowsocksLink(const std::string& data) {
    XrayConfig config;
    config.protocol = "shadowsocks";
    config.network = "tcp";
    config.security = "none";
    
    // 先分离 #name
    std::string body = data;
    size_t hashPos = body.find('#');
    if (hashPos != std::string::npos) {
        body = body.substr(0, hashPos);
    }
    
    // 分离 ?params（如果有）
    std::string params;
    size_t qPos = body.find('?');
    if (qPos != std::string::npos) {
        params = body.substr(qPos + 1);
        body = body.substr(0, qPos);
    }
    
    // 检查是否是 SIP002 格式 (包含 @ 且 @ 前面是 Base64)
    size_t atPos = body.find('@');
    if (atPos != std::string::npos) {
        // SIP002: base64(method:password)@host:port
        std::string userInfo = Base64Decode(body.substr(0, atPos));
        std::string hostPort = body.substr(atPos + 1);
        
        // 如果 base64 解码失败（可能是 method:password 是明文的格式）
        if (userInfo.empty() || userInfo.find(':') == std::string::npos) {
            // 尝试直接作为 method:password
            userInfo = body.substr(0, atPos);
        }
        
        size_t colonPos = userInfo.find(':');
        if (colonPos != std::string::npos) {
            config.encryption = userInfo.substr(0, colonPos);
            config.password = userInfo.substr(colonPos + 1);
        }
        
        // 解析 host:port
        if (hostPort[0] == '[') {
            size_t bracketEnd = hostPort.find(']');
            if (bracketEnd != std::string::npos) {
                config.address = hostPort.substr(1, bracketEnd - 1);
                if (bracketEnd + 1 < hostPort.length() && hostPort[bracketEnd + 1] == ':') {
                    config.port = std::atoi(hostPort.substr(bracketEnd + 2).c_str());
                }
            }
        } else {
            size_t cp = hostPort.rfind(':');
            if (cp != std::string::npos) {
                config.address = hostPort.substr(0, cp);
                config.port = std::atoi(hostPort.substr(cp + 1).c_str());
            } else {
                config.address = hostPort;
            }
        }
    } else {
        // 旧格式: base64(method:password@host:port)
        std::string decoded = Base64Decode(body);
        if (decoded.empty()) return XrayConfig();
        
        size_t at2 = decoded.find('@');
        if (at2 == std::string::npos) return XrayConfig();
        
        std::string userInfo = decoded.substr(0, at2);
        std::string hostPort = decoded.substr(at2 + 1);
        
        size_t colonPos = userInfo.find(':');
        if (colonPos != std::string::npos) {
            config.encryption = userInfo.substr(0, colonPos);
            config.password = userInfo.substr(colonPos + 1);
        }
        
        size_t cp = hostPort.rfind(':');
        if (cp != std::string::npos) {
            config.address = hostPort.substr(0, cp);
            config.port = std::atoi(hostPort.substr(cp + 1).c_str());
        }
    }
    
    if (config.port <= 0) config.port = 443;
    
    // 解析 plugin 参数（如果有）
    if (!params.empty()) {
        auto qp = ParseQueryParams(params);
        // plugin 通常是 v2ray-plugin 或 obfs-local 等，暂不处理
    }
    
    return config;
}

XrayConfig XrayManager::ParseShareLink(const std::string& link) {
    // 去除首尾空白
    std::string trimmed = link;
    while (!trimmed.empty() && (trimmed.front() == ' ' || trimmed.front() == '\n' || trimmed.front() == '\r'))
        trimmed.erase(trimmed.begin());
    while (!trimmed.empty() && (trimmed.back() == ' ' || trimmed.back() == '\n' || trimmed.back() == '\r'))
        trimmed.pop_back();
    
    if (trimmed.substr(0, 8) == "vmess://") {
        return ParseVmessLink(trimmed.substr(8));
    } else if (trimmed.substr(0, 8) == "vless://") {
        return ParseVlessLink(trimmed.substr(8));
    } else if (trimmed.substr(0, 9) == "trojan://") {
        return ParseTrojanLink(trimmed.substr(9));
    } else if (trimmed.substr(0, 5) == "ss://") {
        return ParseShadowsocksLink(trimmed.substr(5));
    }
    
    // 不支持的链接格式
    return XrayConfig();
}

std::string XrayManager::ExtractNameFromLink(const std::string& link) {
    // 从链接中提取 #name 部分
    size_t hashPos = link.rfind('#');
    if (hashPos != std::string::npos && hashPos + 1 < link.length()) {
        return UrlDecode(link.substr(hashPos + 1));
    }
    
    // vmess:// 的名称在 JSON 的 "ps" 字段
    if (link.substr(0, 8) == "vmess://") {
        std::string decoded = Base64Decode(link.substr(8));
        if (!decoded.empty()) {
            return ExtractJsonString(decoded, "ps");
        }
    }
    
    return "";
}

std::vector<DWORD> XrayManager::GetAllProcessIds() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<DWORD> pids;
    for (const auto& pair : processes_) {
        if (pair.second.processId != 0) {
            // 确认进程仍在运行
            DWORD exitCode;
            if (pair.second.hProcess &&
                GetExitCodeProcess(pair.second.hProcess, &exitCode) &&
                exitCode == STILL_ACTIVE) {
                pids.push_back(pair.second.processId);
            }
        }
    }
    return pids;
}

