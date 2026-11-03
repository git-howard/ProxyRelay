#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wininet.h>
#include "ClashManager.h"
#include "Database.h"
#include "Utils.h"
#include <sstream>
#include <fstream>
#include <filesystem>
#include <regex>
#include <chrono>
#include <ctime>
#include <set>

#pragma comment(lib, "wininet.lib")

ClashManager& ClashManager::Instance() {
    static ClashManager instance;
    return instance;
}

ClashManager::~ClashManager() {
    StopAutoUpdate();
    StopAll();
}

bool ClashManager::Initialize() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    char exePath[MAX_PATH];
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    std::string exeDir = std::filesystem::path(exePath).parent_path().string();
    
    // 查找可执行文件
    const char* candidates[] = {
        "mihomo-windows-amd64.exe",
        "mihomo.exe",
        "clash-meta.exe",
        "clash.exe"
    };

    for (const char* name : candidates) {
        std::string path1 = exeDir + "\\" + name;
        if (std::filesystem::exists(path1)) {
            clashPath_ = path1;
            Utils::Log("Clash found: " + clashPath_);
            return true;
        }

        std::string pathParent = exeDir + "\\..\\" + name;
        if (std::filesystem::exists(pathParent)) {
            clashPath_ = std::filesystem::canonical(pathParent).string();
            Utils::Log("Clash found: " + clashPath_);
            return true;
        }

        std::string path2 = name;
        if (std::filesystem::exists(path2)) {
            clashPath_ = std::filesystem::absolute(path2).string();
            Utils::Log("Clash found: " + clashPath_);
            return true;
        }
    }
    
    Utils::Log("Clash/Mihomo not found, clash upstream will not be available");
    return false;
}

static HANDLE GetClashJobObject() {
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

// ========== 统一单一 Mihomo 实例管理 (方案四) ==========

// 字符串转义，用于 YAML 单行双引号字符串
static std::string EscapeYamlValue(const std::string& str) {
    std::string res;
    for (char c : str) {
        if (c == '\\') res += "\\\\";
        else if (c == '\"') res += "\\\"";
        else if (c == '\n') res += "\\n";
        else if (c == '\r') res += "\\r";
        else res += c;
    }
    return res;
}

// 检查端口是否被系统占用
static bool IsPortFreeInSystem(int port) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return false;
    
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((u_short)port);
    
    bool free = (bind(sock, (sockaddr*)&addr, sizeof(addr)) == 0);
    closesocket(sock);
    return free;
}

// 提取 clashConfig 中的 proxies 节点列表（每个节点一个单独的完整 string）
static std::vector<std::string> ExtractProxiesFromConfig(const std::string& configYaml) {
    std::vector<std::string> proxyItems;
    std::istringstream stream(configYaml);
    std::string line;
    bool inProxies = false;
    std::string currentItem;

    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();

        // 检查是否遇到 proxies: 顶级键
        if (!inProxies) {
            std::string trimmed = line;
            size_t start = trimmed.find_first_not_of(" \t");
            if (start != std::string::npos) trimmed = trimmed.substr(start);
            if (trimmed.rfind("proxies:", 0) == 0) {
                inProxies = true;
            }
            continue;
        }

        // 检查是否遇到了下一个顶级键（行首没有缩进，且包含冒号，如 proxy-groups: 或 rules:）
        if (!line.empty() && line[0] != ' ' && line[0] != '\t' && line[0] != '#' && line[0] != '-') {
            break;
        }

        // 检查是否是新的代理条目起始行（例如以 "- " 开头）
        size_t firstNonSpace = line.find_first_not_of(" \t");
        if (firstNonSpace != std::string::npos && line[firstNonSpace] == '-') {
            if (!currentItem.empty()) {
                proxyItems.push_back(currentItem);
                currentItem.clear();
            }
            currentItem = "  " + line.substr(firstNonSpace);
        } else if (!currentItem.empty()) {
            if (firstNonSpace == std::string::npos) {
                currentItem += "\n";
            } else {
                currentItem += "\n    " + line.substr(firstNonSpace);
            }
        }
    }

    if (!currentItem.empty()) {
        proxyItems.push_back(currentItem);
    }

    return proxyItems;
}

// 从单个代理定义条目中提取节点名称
static std::string ExtractNodeNameFromProxyItem(const std::string& proxyItem) {
    static const std::regex nameRegex(R"re(name\s*:\s*(?:"([^"]*)"|'([^']*)'|([^,\r\n}]+)))re");
    std::smatch m;
    if (std::regex_search(proxyItem, m, nameRegex)) {
        std::string raw;
        if (m[1].matched) raw = m[1].str();
        else if (m[2].matched) raw = m[2].str();
        else if (m[3].matched) raw = m[3].str();

        size_t start = raw.find_first_not_of(" \t");
        if (start != std::string::npos) {
            size_t end = raw.find_last_not_of(" \t");
            return raw.substr(start, end - start + 1);
        }
    }
    return "";
}

// 替换代理定义中的节点名称
static std::string ReplaceNodeNameInProxyItem(const std::string& proxyItem, const std::string& newName) {
    static const std::regex nameRegex(R"re((name\s*:\s*)(?:"[^"]*"|'[^']*'|[^,\r\n}]+))re");
    std::string safeNewName = "\"" + EscapeYamlValue(newName) + "\"";
    return std::regex_replace(proxyItem, nameRegex, "$1" + safeNewName, std::regex_constants::format_first_only);
}

bool ClashManager::IsUnifiedAliveInternal() {
    if (!unifiedProcess_) return false;
    DWORD exitCode = 0;
    if (GetExitCodeProcess(unifiedProcess_, &exitCode)) {
        return exitCode == STILL_ACTIVE;
    }
    return false;
}

void ClashManager::StopUnifiedInternal() {
    if (unifiedProcess_) {
        TerminateProcess(unifiedProcess_, 0);
        WaitForSingleObject(unifiedProcess_, 2000);
        CloseHandle(unifiedProcess_);
        CloseHandle(unifiedThread_);
        unifiedProcess_ = nullptr;
        unifiedThread_ = nullptr;
        unifiedProcessId_ = 0;
        Utils::Log("Unified Clash process terminated");
    }
}

int ClashManager::AllocatePortForPortId(int portId, const std::map<int, int>& existingMap) {
    // 1. 如果现有映射中有，且符合范围，优先沿用
    auto it = existingMap.find(portId);
    if (it != existingMap.end() && it->second >= PORT_RANGE_START && it->second < PORT_RANGE_END) {
        return it->second;
    }

    // 2. 首选固定哈希端口：30001 ~ 39900
    int preferred = PORT_RANGE_START + (portId % 9000) + 1;
    
    auto isPortAssigned = [&existingMap](int port) {
        for (const auto& pair : existingMap) {
            if (pair.second == port) return true;
        }
        return false;
    };

    if (!isPortAssigned(preferred) && IsPortFreeInSystem(preferred)) {
        return preferred;
    }

    // 3. 递增寻找未分配且系统空闲端口
    for (int p = PORT_RANGE_START + 1; p < PORT_RANGE_END; ++p) {
        if (!isPortAssigned(p) && IsPortFreeInSystem(p)) {
            return p;
        }
    }
    return 0;
}

bool ClashManager::StartOrReloadUnifiedInternal() {
    if (clashPath_.empty()) {
        Utils::LogError("Clash executable not available, cannot start unified instance");
        return false;
    }

    // 1. 获取所有启用的 clash 代理端口
    auto allEnabled = Database::Instance().GetEnabledProxyPorts();
    std::vector<ProxyPort> clashPorts;
    for (const auto& p : allEnabled) {
        if (p.upstreamType == "clash") {
            clashPorts.push_back(p);
        }
    }

    // 如果没有任何 clash 端口处于启用状态，停止统一实例
    if (clashPorts.empty()) {
        StopUnifiedInternal();
        portToLocalSocksPort_.clear();
        lastUnifiedConfigContent_.clear();
        return true;
    }

    // 2. 为每个启用的端口分配/保留本地 listener 端口
    std::map<int, int> newPortMap;
    // 先继承已有的映射
    for (const auto& p : clashPorts) {
        auto it = portToLocalSocksPort_.find(p.id);
        if (it != portToLocalSocksPort_.end()) {
            newPortMap[p.id] = it->second;
        }
    }
    // 为新增的端口分配新端口
    for (const auto& p : clashPorts) {
        if (newPortMap.find(p.id) == newPortMap.end()) {
            int allocated = AllocatePortForPortId(p.id, newPortMap);
            if (allocated > 0) {
                newPortMap[p.id] = allocated;
            } else {
                Utils::LogError("Failed to allocate local port for Clash port ID " + std::to_string(p.id));
            }
        }
    }

    // 3. 提取节点并构建 listeners 与 proxies 列表
    std::map<std::string, std::string> uniqueProxies; // proxyName -> proxyYamlBlock
    struct ListenerBinding {
        int portId;
        int localPort;
        std::string targetProxyName;
    };
    std::vector<ListenerBinding> bindings;

    for (const auto& p : clashPorts) {
        if (newPortMap.find(p.id) == newPortMap.end()) continue;
        int localPort = newPortMap[p.id];

        std::vector<std::string> items = ExtractProxiesFromConfig(p.clashConfig);
        std::string proxyItem;
        std::string nodeName = p.clashNodeName;

        if (!items.empty()) {
            proxyItem = items[0];
            std::string extractedName = ExtractNodeNameFromProxyItem(proxyItem);
            if (!extractedName.empty()) {
                nodeName = extractedName;
            }
        }

        // 如果仍为空，兜底构造
        if (proxyItem.empty()) {
            if (nodeName.empty()) nodeName = "node_" + std::to_string(p.id);
            std::string safeName = EscapeYamlValue(nodeName);
            proxyItem = "  - name: \"" + safeName + "\"\n"
                        "    type: socks5\n"
                        "    server: " + (p.upstreamHost.empty() ? "127.0.0.1" : p.upstreamHost) + "\n"
                        "    port: " + std::to_string(p.upstreamPort > 0 ? p.upstreamPort : 1080);
        }

        if (nodeName.empty()) {
            nodeName = "node_" + std::to_string(p.id);
            proxyItem = ReplaceNodeNameInProxyItem(proxyItem, nodeName);
        }

        // 检查 nodeName 是否已存在
        std::string finalProxyName = nodeName;
        auto existing = uniqueProxies.find(nodeName);
        if (existing != uniqueProxies.end()) {
            // 如果同名但内容完全不同，为了防止冲突重命名节点
            if (existing->second != proxyItem) {
                finalProxyName = nodeName + " (" + std::to_string(p.id) + ")";
                proxyItem = ReplaceNodeNameInProxyItem(proxyItem, finalProxyName);
                uniqueProxies[finalProxyName] = proxyItem;
            }
        } else {
            uniqueProxies[finalProxyName] = proxyItem;
        }

        bindings.push_back({ p.id, localPort, finalProxyName });
    }

    // 4. 组装 unified YAML 文本
    // 选取一个未被 listener 使用的端口作为主 mixed-port
    int mainPort = PORT_RANGE_START;
    for (const auto& pair : newPortMap) {
        if (pair.second == mainPort) {
            mainPort = PORT_RANGE_START - 1;
            break;
        }
    }

    std::ostringstream oss;
    oss << "mixed-port: " << mainPort << "\n";
    oss << "allow-lan: false\n";
    oss << "mode: rule\n";
    oss << "log-level: error\n";
    oss << "ipv6: false\n";
    oss << "find-process-mode: off\n\n";

    oss << "listeners:\n";
    for (const auto& b : bindings) {
        oss << "  - name: \"listener_" << b.portId << "\"\n";
        oss << "    type: mixed\n";
        oss << "    port: " << b.localPort << "\n";
        oss << "    listen: 127.0.0.1\n";
        oss << "    proxy: \"" << EscapeYamlValue(b.targetProxyName) << "\"\n";
    }

    oss << "\nproxies:\n";
    for (const auto& pair : uniqueProxies) {
        oss << pair.second << "\n";
    }

    oss << "\nrules:\n";
    oss << "  - MATCH,DIRECT\n";

    std::string newConfigContent = oss.str();

    // 检查配置是否未发生变化且当前实例存活
    if (IsUnifiedAliveInternal() && newConfigContent == lastUnifiedConfigContent_) {
        portToLocalSocksPort_ = newPortMap;
        return true;
    }

    // 5. 先终止旧实例
    StopUnifiedInternal();

    // 6. 写入完整的聚合配置文件
    std::filesystem::create_directories("data");
    unifiedConfigPath_ = "data/clash_unified.yaml";
    std::ofstream out(unifiedConfigPath_);
    if (!out.is_open()) {
        Utils::LogError("Failed to write unified clash config: " + unifiedConfigPath_);
        return false;
    }
    out << newConfigContent;
    out.close();

    // 7. 启动单一统一实例
    std::string cmdLine = "\"" + clashPath_ + "\" -d data -f \"" + 
                          std::filesystem::absolute(unifiedConfigPath_).string() + "\"";
    
    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    PROCESS_INFORMATION pi = {};
    DWORD creationFlags = CREATE_NO_WINDOW | DETACHED_PROCESS;

    if (!CreateProcessA(
        nullptr,
        const_cast<char*>(cmdLine.c_str()),
        nullptr, nullptr, FALSE,
        creationFlags,
        nullptr, nullptr,
        &si, &pi)) {
        Utils::LogError("Failed to start unified clash process, error: " + std::to_string(GetLastError()));
        return false;
    }

    HANDLE hJob = GetClashJobObject();
    if (hJob) {
        AssignProcessToJobObject(hJob, pi.hProcess);
    }

    // 7. 等待 listener 端口就绪（最多 2500ms）
    bool portReady = false;
    int testPort = bindings.empty() ? mainPort : bindings[0].localPort;
    for (int attempt = 0; attempt < 50; ++attempt) {
        if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0) {
            break; // 进程崩溃退出
        }
        SOCKET checkSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (checkSock != INVALID_SOCKET) {
            sockaddr_in testAddr = {};
            testAddr.sin_family = AF_INET;
            testAddr.sin_port = htons((u_short)testPort);
            inet_pton(AF_INET, "127.0.0.1", &testAddr.sin_addr);
            unsigned long nonBlock = 1;
            ioctlsocket(checkSock, FIONBIO, &nonBlock);
            connect(checkSock, (sockaddr*)&testAddr, sizeof(testAddr));
            fd_set writeFds;
            FD_ZERO(&writeFds);
            FD_SET(checkSock, &writeFds);
            timeval tv = {0, 50000};
            if (select(0, nullptr, &writeFds, nullptr, &tv) > 0) {
                int optErr = 0;
                int optLen = sizeof(optErr);
                if (getsockopt(checkSock, SOL_SOCKET, SO_ERROR, (char*)&optErr, &optLen) == 0 && optErr == 0) {
                    portReady = true;
                    closesocket(checkSock);
                    break;
                }
            }
            closesocket(checkSock);
        }
        Sleep(50);
    }

    if (!portReady && WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0) {
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        Utils::LogError("Unified Clash process exited immediately with code: " + std::to_string(exitCode));
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }

    unifiedProcess_ = pi.hProcess;
    unifiedThread_ = pi.hThread;
    unifiedProcessId_ = pi.dwProcessId;
    portToLocalSocksPort_ = newPortMap;
    lastUnifiedConfigContent_ = newConfigContent;

    Utils::Log("Unified Clash process started successfully, PID: " + std::to_string(unifiedProcessId_) + 
               ", active listeners: " + std::to_string(bindings.size()));

    return true;
}

bool ClashManager::StartOrReloadUnified() {
    std::lock_guard<std::mutex> lock(mutex_);
    return StartOrReloadUnifiedInternal();
}

int ClashManager::StartClash(int portId, const std::string& /*configYaml*/) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (IsUnifiedAliveInternal()) {
        auto it = portToLocalSocksPort_.find(portId);
        if (it != portToLocalSocksPort_.end()) {
            return it->second;
        }
    }
    if (StartOrReloadUnifiedInternal()) {
        auto it = portToLocalSocksPort_.find(portId);
        if (it != portToLocalSocksPort_.end()) {
            return it->second;
        }
    }
    return 0;
}

void ClashManager::StopClash(int portId) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (portToLocalSocksPort_.erase(portId) > 0) {
        if (portToLocalSocksPort_.empty()) {
            StopUnifiedInternal();
        } else {
            StartOrReloadUnifiedInternal();
        }
    }
}

void ClashManager::StopAll() {
    std::lock_guard<std::mutex> lock(mutex_);
    StopUnifiedInternal();
    if (!unifiedConfigPath_.empty()) {
        try { std::filesystem::remove(unifiedConfigPath_); } catch (...) {}
    }
    portToLocalSocksPort_.clear();
    lastUnifiedConfigContent_.clear();
}

int ClashManager::GetLocalSocksPort(int portId) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsUnifiedAliveInternal()) return 0;
    auto it = portToLocalSocksPort_.find(portId);
    if (it != portToLocalSocksPort_.end()) {
        return it->second;
    }
    return 0;
}

bool ClashManager::IsRunning(int portId) {
    std::lock_guard<std::mutex> lock(mutex_);
    return IsUnifiedAliveInternal() && (portToLocalSocksPort_.find(portId) != portToLocalSocksPort_.end());
}

int ClashManager::FindAvailablePort() {
    for (int p = PORT_RANGE_START; p < PORT_RANGE_END; ++p) {
        if (IsPortFreeInSystem(p)) return p;
    }
    return 0;
}

// ========== 订阅管理功能 ==========

static void ParseSubscriptionHeaders(const std::string& headers, ClashManager::SubscriptionUserInfo& info) {
    std::string lower = headers;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c){ return (char)std::tolower(c); });
    
    // 检查 profile-web-page-url
    size_t webPos = lower.find("profile-web-page-url:");
    if (webPos != std::string::npos) {
        size_t lineEnd = headers.find_first_of("\r\n", webPos);
        size_t start = webPos + strlen("profile-web-page-url:");
        std::string wUrl = headers.substr(start, (lineEnd == std::string::npos ? headers.size() : lineEnd) - start);
        while (!wUrl.empty() && isspace((unsigned char)wUrl.front())) wUrl.erase(wUrl.begin());
        while (!wUrl.empty() && isspace((unsigned char)wUrl.back())) wUrl.pop_back();
        if (!wUrl.empty()) info.websiteUrl = wUrl;
    }

    // 检查 subscription-userinfo
    size_t infoPos = lower.find("subscription-userinfo:");
    if (infoPos != std::string::npos) {
        size_t lineEnd = headers.find_first_of("\r\n", infoPos);
        size_t start = infoPos + strlen("subscription-userinfo:");
        std::string line = headers.substr(start, (lineEnd == std::string::npos ? headers.size() : lineEnd) - start);
        
        static const std::regex upRegex(R"(upload\s*=\s*(\d+))", std::regex::icase);
        static const std::regex downRegex(R"(download\s*=\s*(\d+))", std::regex::icase);
        static const std::regex totalRegex(R"(total\s*=\s*(\d+))", std::regex::icase);
        static const std::regex expRegex(R"(expire\s*=\s*(\d+))", std::regex::icase);
        static const std::regex startRegex(R"((?:start|reset|begin|created|start_time|start-time|start_date)\s*=\s*(\d+))", std::regex::icase);
        
        std::smatch m;
        if (std::regex_search(line, m, upRegex)) {
            try { info.uploadBytes = std::stoll(m[1].str()); } catch (...) {}
        }
        if (std::regex_search(line, m, downRegex)) {
            try { info.downloadBytes = std::stoll(m[1].str()); } catch (...) {}
        }
        if (std::regex_search(line, m, totalRegex)) {
            try { info.totalBytes = std::stoll(m[1].str()); } catch (...) {}
        }
        if (std::regex_search(line, m, expRegex)) {
            try {
                int64_t expSec = std::stoll(m[1].str());
                if (expSec > 0) {
                    std::time_t t = (std::time_t)expSec;
                    std::tm tmBuf = {};
                    localtime_s(&tmBuf, &t);
                    char buf[64];
                    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmBuf);
                    info.expireTime = buf;
                } else {
                    info.expireTime = "长期有效";
                }
            } catch (...) {}
        }
        if (std::regex_search(line, m, startRegex)) {
            try {
                int64_t startSec = std::stoll(m[1].str());
                if (startSec > 0) {
                    std::time_t t = (std::time_t)startSec;
                    std::tm tmBuf = {};
                    localtime_s(&tmBuf, &t);
                    char buf[32];
                    std::strftime(buf, sizeof(buf), "%Y-%m-%d", &tmBuf);
                    info.startDate = buf;
                }
            } catch (...) {}
        }
    }

    // 检查独立标头 subscription-start / subscription-start-date / x-subscription-start
    if (info.startDate.empty()) {
        size_t subStartPos = lower.find("subscription-start");
        if (subStartPos != std::string::npos) {
            size_t colonPos = headers.find(':', subStartPos);
            if (colonPos != std::string::npos) {
                size_t lineEnd = headers.find_first_of("\r\n", colonPos);
                std::string val = headers.substr(colonPos + 1, (lineEnd == std::string::npos ? headers.size() : lineEnd) - colonPos - 1);
                while (!val.empty() && isspace((unsigned char)val.front())) val.erase(val.begin());
                while (!val.empty() && isspace((unsigned char)val.back())) val.pop_back();
                if (val.length() >= 10 && val.find('-') != std::string::npos) {
                    int y = 0, mo = 0, d = 0;
                    if (sscanf_s(val.c_str(), "%d-%d-%d", &y, &mo, &d) == 3) {
                        char buf[32];
                        sprintf_s(buf, "%04d-%02d-%02d", y, mo, d);
                        info.startDate = buf;
                    }
                } else {
                    try {
                        int64_t ts = std::stoll(val);
                        if (ts > 0) {
                            std::time_t t = (std::time_t)ts;
                            std::tm tmBuf = {};
                            localtime_s(&tmBuf, &t);
                            char buf[32];
                            std::strftime(buf, sizeof(buf), "%Y-%m-%d", &tmBuf);
                            info.startDate = buf;
                        }
                    } catch (...) {}
                }
            }
        }
    }
}

void ClashManager::ParseSubscriptionContentUserInfo(const std::string& content, ClashManager::SubscriptionUserInfo& info) {
    if (content.empty()) return;
    std::string head = content.substr(0, std::min<size_t>(content.size(), 3000));
    std::smatch m;
    if (info.totalBytes == 0) {
        static const std::regex totalReg(R"((?:#|//|\b)(?:total|总流量)\s*[:=]\s*(\d+))", std::regex::icase);
        if (std::regex_search(head, m, totalReg)) {
            try { info.totalBytes = std::stoll(m[1].str()); } catch (...) {}
        }
    }
    if (info.uploadBytes == 0) {
        static const std::regex upReg(R"((?:#|//|\b)(?:upload|已用上行|上行流量)\s*[:=]\s*(\d+))", std::regex::icase);
        if (std::regex_search(head, m, upReg)) {
            try { info.uploadBytes = std::stoll(m[1].str()); } catch (...) {}
        }
    }
    if (info.downloadBytes == 0) {
        static const std::regex downReg(R"((?:#|//|\b)(?:download|已用下行|下行流量)\s*[:=]\s*(\d+))", std::regex::icase);
        if (std::regex_search(head, m, downReg)) {
            try { info.downloadBytes = std::stoll(m[1].str()); } catch (...) {}
        }
    }
    if (info.expireTime.empty()) {
        static const std::regex expReg(R"((?:#|//|\b)(?:expire|到期时间|过期时间|有效期)\s*[:=]\s*([0-9- :]+))", std::regex::icase);
        if (std::regex_search(head, m, expReg)) {
            std::string expVal = m[1].str();
            while (!expVal.empty() && isspace((unsigned char)expVal.back())) expVal.pop_back();
            if (!expVal.empty()) info.expireTime = expVal;
        }
    }
    if (info.startDate.empty()) {
        // 匹配 YYYY-MM-DD 格式的起始/开始日期注释
        static const std::regex startDateReg(R"((?:#|//|\b)(?:start_date|start|begin|起始时间|开始时间|起始日期|开始日期|流量起始|套餐开始|生效时间)\s*[:=]\s*([0-9]{4}-[0-9]{1,2}-[0-9]{1,2}))", std::regex::icase);
        if (std::regex_search(head, m, startDateReg)) {
            std::string dateVal = m[1].str();
            int y = 0, mo = 0, d = 0;
            if (sscanf_s(dateVal.c_str(), "%d-%d-%d", &y, &mo, &d) == 3) {
                char buf[32];
                sprintf_s(buf, "%04d-%02d-%02d", y, mo, d);
                info.startDate = buf;
            }
        }
    }
    if (info.startDate.empty()) {
        // 匹配 UNIX 秒时间戳
        static const std::regex startTsReg(R"((?:#|//|\b)(?:start_time|start|begin|created)\s*[:=]\s*(\d{10}))", std::regex::icase);
        if (std::regex_search(head, m, startTsReg)) {
            try {
                int64_t ts = std::stoll(m[1].str());
                if (ts > 0) {
                    std::time_t t = (std::time_t)ts;
                    std::tm tmBuf = {};
                    localtime_s(&tmBuf, &t);
                    char buf[32];
                    std::strftime(buf, sizeof(buf), "%Y-%m-%d", &tmBuf);
                    info.startDate = buf;
                }
            } catch (...) {}
        }
    }
}

std::string ClashManager::DownloadSubscription(const std::string& url, SubscriptionUserInfo* outInfo) {
    Utils::Log("Downloading Clash subscription: " + url);
    
    // 使用兼容 clash.meta / clash-verge 的标准客户端 User-Agent
    const char* userAgent = "clash.meta/v1.18.0 (ProxyRelay/1.0)";
    HINTERNET hInternet = InternetOpenA(
        userAgent, 
        INTERNET_OPEN_TYPE_PRECONFIG, 
        NULL, NULL, 0
    );
    if (!hInternet) {
        Utils::LogError("InternetOpen failed, error: " + std::to_string(GetLastError()));
        return "";
    }
    
    // 设置超时
    DWORD timeout = 30000; // 30 秒
    InternetSetOptionA(hInternet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOptionA(hInternet, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
    
    const char* customHeaders = "User-Agent: clash.meta/v1.18.0\r\nAccept: application/yaml, text/yaml, */*\r\n";
    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_KEEP_CONNECTION;

    HINTERNET hUrl = InternetOpenUrlA(
        hInternet, url.c_str(), customHeaders, (DWORD)strlen(customHeaders),
        flags | INTERNET_FLAG_SECURE, 0
    );
    if (!hUrl) {
        // HTTPS 失败时尝试不强制 SECURE 标记
        hUrl = InternetOpenUrlA(
            hInternet, url.c_str(), customHeaders, (DWORD)strlen(customHeaders),
            flags, 0
        );
    }
    if (!hUrl) {
        Utils::LogError("InternetOpenUrl failed, error: " + std::to_string(GetLastError()));
        InternetCloseHandle(hInternet);
        return "";
    }

    // 检查 HTTP 状态码
    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    if (HttpQueryInfoA(hUrl, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &statusCode, &statusSize, NULL)) {
        if (statusCode >= 400) {
            Utils::LogError("Download subscription failed with HTTP status code: " + std::to_string(statusCode));
            InternetCloseHandle(hUrl);
            InternetCloseHandle(hInternet);
            return "";
        }
    }

    // 解析订阅响应标头中的用户信息
    if (outInfo) {
        *outInfo = SubscriptionUserInfo();
        size_t protoPos = url.find("://");
        if (protoPos != std::string::npos) {
            size_t pathPos = url.find('/', protoPos + 3);
            outInfo->websiteUrl = (pathPos == std::string::npos) ? url : url.substr(0, pathPos);
        }
        
        DWORD rawSize = 0;
        HttpQueryInfoA(hUrl, HTTP_QUERY_RAW_HEADERS_CRLF, NULL, &rawSize, NULL);
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && rawSize > 0) {
            std::string rawHeaders(rawSize + 1, '\0');
            if (HttpQueryInfoA(hUrl, HTTP_QUERY_RAW_HEADERS_CRLF, &rawHeaders[0], &rawSize, NULL)) {
                rawHeaders.resize(rawSize);
                ParseSubscriptionHeaders(rawHeaders, *outInfo);
            }
        }
    }
    
    std::string result;
    char buffer[8192];
    DWORD bytesRead;
    while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        result.append(buffer, bytesRead);
    }
    
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);

    if (outInfo) {
        ParseSubscriptionContentUserInfo(result, *outInfo);
    }
    
    Utils::Log("Downloaded subscription, size: " + std::to_string(result.size()) + " bytes");
    return result;
}

// 辅助函数：清洗 YAML 属性值（去除前后空格、引号、行尾注释）
static std::string CleanYamlValue(const std::string& raw) {
    if (raw.empty()) return "";
    
    // 跳过起始空白
    size_t s = raw.find_first_not_of(" \t\r\n");
    if (s == std::string::npos) return "";
    
    // 如果带引号
    if (raw[s] == '"' || raw[s] == '\'') {
        char quote = raw[s];
        size_t e = s + 1;
        while (e < raw.size() && raw[e] != quote) {
            if (raw[e] == '\\' && e + 1 < raw.size()) e += 2;
            else e++;
        }
        return raw.substr(s + 1, e - s - 1);
    }
    
    // 无引号值：截断行内注释 #
    std::string val = raw.substr(s);
    size_t hashPos = val.find('#');
    if (hashPos != std::string::npos) {
        val = val.substr(0, hashPos);
    }
    
    // 去除尾部空白和可能残留的引号/逗号
    size_t e = val.find_last_not_of(" \t\r\n,\"'");
    if (e == std::string::npos) return "";
    return val.substr(0, e + 1);
}

// 辅助函数：解析 Flow 格式（花括号内内容）
static void ParseFlowMapping(const std::string& flowStr, ClashNode& node) {
    size_t i = 0;
    size_t len = flowStr.size();
    while (i < len) {
        // 跳过空白、逗号、花括号
        while (i < len && (flowStr[i] == ' ' || flowStr[i] == '\t' || flowStr[i] == ',' || flowStr[i] == '{' || flowStr[i] == '}')) {
            i++;
        }
        if (i >= len) break;
        
        // 解析 key
        size_t keyStart = i;
        while (i < len && flowStr[i] != ':' && flowStr[i] != ' ' && flowStr[i] != '\t' && flowStr[i] != '}' && flowStr[i] != ',') {
            i++;
        }
        std::string key = flowStr.substr(keyStart, i - keyStart);
        
        // 跳过冒号前后的空白
        while (i < len && (flowStr[i] == ' ' || flowStr[i] == '\t')) i++;
        if (i < len && flowStr[i] == ':') i++;
        while (i < len && (flowStr[i] == ' ' || flowStr[i] == '\t')) i++;
        
        // 解析 value
        std::string val;
        if (i < len && (flowStr[i] == '"' || flowStr[i] == '\'')) {
            char quote = flowStr[i++];
            size_t valStart = i;
            while (i < len && flowStr[i] != quote) {
                if (flowStr[i] == '\\' && i + 1 < len) i += 2;
                else i++;
            }
            val = flowStr.substr(valStart, i - valStart);
            if (i < len && flowStr[i] == quote) i++;
        } else {
            size_t valStart = i;
            while (i < len && flowStr[i] != ',' && flowStr[i] != '}') {
                i++;
            }
            val = flowStr.substr(valStart, i - valStart);
            size_t end = val.find_last_not_of(" \t\r\n");
            if (end != std::string::npos) val = val.substr(0, end + 1);
        }
        
        // 赋值
        if (key == "name") {
            if (node.name.empty()) node.name = val;
        } else if (key == "server") {
            if (node.server.empty()) node.server = val;
        } else if (key == "type") {
            if (node.type.empty()) node.type = val;
        } else if (key == "port") {
            if (node.port == 0) {
                std::string digits;
                for (char c : val) {
                    if (isdigit((unsigned char)c)) digits += c;
                    else if (!digits.empty()) break;
                }
                if (!digits.empty()) {
                    try { node.port = std::stoi(digits); } catch (...) {}
                }
            }
        }
    }
}

// 辅助函数：解析 Block 单行中的 key-value
static void ParseKeyValue(const std::string& line, ClashNode& node) {
    size_t colon = line.find(':');
    if (colon == std::string::npos) return;
    
    std::string key = line.substr(0, colon);
    size_t ks = key.find_first_not_of(" \t");
    size_t ke = key.find_last_not_of(" \t");
    if (ks == std::string::npos || ke == std::string::npos) return;
    key = key.substr(ks, ke - ks + 1);
    
    std::string val = CleanYamlValue(line.substr(colon + 1));
    
    if (key == "name") {
        if (node.name.empty()) node.name = val;
    } else if (key == "server") {
        if (node.server.empty()) node.server = val;
    } else if (key == "type") {
        if (node.type.empty()) node.type = val;
    } else if (key == "port") {
        if (node.port == 0) {
            std::string digits;
            for (char c : val) {
                if (isdigit((unsigned char)c)) digits += c;
                else if (!digits.empty()) break;
            }
            if (!digits.empty()) {
                try { node.port = std::stoi(digits); } catch (...) {}
            }
        }
    }
}

std::vector<ClashNode> ClashManager::ParseSubscriptionNodes(const std::string& yamlContent) {
    std::vector<ClashNode> nodes;
    if (yamlContent.empty()) return nodes;
    
    std::string content = yamlContent;
    
    // 1. 去除 UTF-8 BOM
    if (content.size() >= 3 && 
        (unsigned char)content[0] == 0xEF && 
        (unsigned char)content[1] == 0xBB && 
        (unsigned char)content[2] == 0xBF) {
        content = content.substr(3);
    }
    
    // 2. 如果没有 proxies: 或 Proxy:，尝试 Base64 解码
    if (content.find("proxies:") == std::string::npos && 
        content.find("Proxy:") == std::string::npos &&
        content.find("server:") == std::string::npos) {
        std::string decoded = Utils::Base64Decode(content);
        if (decoded.find("proxies:") != std::string::npos || 
            decoded.find("Proxy:") != std::string::npos ||
            decoded.find("server:") != std::string::npos) {
            content = decoded;
            Utils::Log("Decoded subscription content from Base64");
        }
    }
    
    // 3. 如果依然没有 proxies: / Proxy: 顶层键，自动补充 proxies:
    if (content.find("proxies:") == std::string::npos && 
        content.find("Proxy:") == std::string::npos) {
        size_t first = content.find_first_not_of(" \t\r\n");
        if (first != std::string::npos) {
            if (content[first] == '{') {
                content = "proxies:\n  - " + content;
            } else if (content[first] == '-') {
                content = "proxies:\n" + content;
            } else if (content.find("server:") != std::string::npos || content.find("name:") != std::string::npos) {
                if (content.find("- ") != std::string::npos || content.find("-{") != std::string::npos) {
                    content = "proxies:\n" + content;
                } else {
                    content = "proxies:\n  - " + content;
                }
            }
        }
    }
    
    std::istringstream stream(content);
    std::string line;
    bool inProxies = false;
    std::string currentNodeYaml;
    ClashNode currentNode;
    bool hasNode = false;
    
    auto flushNode = [&]() {
        if (hasNode) {
            currentNode.rawYaml = currentNodeYaml;
            std::string t = Utils::ToLower(currentNode.type);
            bool isPolicyGroup = (t == "select" || t == "url-test" || t == "fallback" || t == "load-balance" || t == "relay" || t == "direct" || t == "reject");
            bool isValidServer = !currentNode.server.empty() && currentNode.server != "127.0.0.1" && currentNode.server != "0.0.0.0" && currentNode.server != "localhost";
            bool isValidPort = currentNode.port > 0 && currentNode.port <= 65535;
            if (!currentNode.name.empty() && isValidServer && isValidPort && !isPolicyGroup) {
                nodes.push_back(currentNode);
            }
            hasNode = false;
            currentNode = ClashNode();
            currentNodeYaml.clear();
        }
    };
    
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        
        size_t firstNonSpace = line.find_first_not_of(" \t");
        if (firstNonSpace == std::string::npos) {
            if (hasNode) currentNodeYaml += line + "\n";
            continue;
        }
        
        if (line[firstNonSpace] == '#') {
            continue;
        }
        
        // 顶层键检测（无缩进且不是列表项 '-'）
        if (firstNonSpace == 0 && line[0] != '-') {
            std::string trimmed = line;
            if (trimmed.rfind("proxies:", 0) == 0 || trimmed.rfind("Proxy:", 0) == 0) {
                flushNode();
                inProxies = true;
                continue;
            } else if (inProxies) {
                // 进入了下一个顶层 key
                flushNode();
                inProxies = false;
                continue;
            }
        }
        
        if (!inProxies) continue;
        
        // 检测新节点（以 '-' 开头）
        bool isNewNode = false;
        if (line[firstNonSpace] == '-') {
            if (firstNonSpace + 1 >= line.size() || 
                line[firstNonSpace + 1] == ' ' || 
                line[firstNonSpace + 1] == '\t' || 
                line[firstNonSpace + 1] == '{') {
                isNewNode = true;
            }
        }
        
        if (isNewNode) {
            flushNode();
            hasNode = true;
            currentNodeYaml = line + "\n";
            
            size_t braceStart = line.find('{');
            if (braceStart != std::string::npos) {
                size_t braceEnd = line.rfind('}');
                std::string flowContent;
                if (braceEnd != std::string::npos && braceEnd > braceStart) {
                    flowContent = line.substr(braceStart + 1, braceEnd - braceStart - 1);
                } else {
                    flowContent = line.substr(braceStart + 1);
                }
                ParseFlowMapping(flowContent, currentNode);
                flushNode();
            } else {
                size_t afterDash = firstNonSpace + 1;
                while (afterDash < line.size() && (line[afterDash] == ' ' || line[afterDash] == '\t')) afterDash++;
                if (afterDash < line.size()) {
                    ParseKeyValue(line.substr(afterDash), currentNode);
                }
            }
        } else if (hasNode) {
            currentNodeYaml += line + "\n";
            ParseKeyValue(line.substr(firstNonSpace), currentNode);
        }
    }
    
    flushNode();
    
    Utils::Log("Parsed " + std::to_string(nodes.size()) + " nodes from subscription");
    return nodes;
}

std::string ClashManager::GenerateNodeConfig(const ClashNode& node, int mixedPort) {
    std::ostringstream oss;
    oss << "mixed-port: " << mixedPort << "\n";
    oss << "allow-lan: false\n";
    oss << "mode: rule\n";
    oss << "log-level: error\n";
    oss << "\n";
    oss << "proxies:\n";
    
    // 如果 rawYaml 为空，兜底生成基础节点项
    if (node.rawYaml.empty()) {
        std::string safeName = std::regex_replace(node.name, std::regex(R"(")"), "\\\"");
        std::string t = node.type.empty() ? "socks5" : node.type;
        oss << "  - name: \"" << safeName << "\"\n";
        oss << "    type: " << t << "\n";
        oss << "    server: " << node.server << "\n";
        oss << "    port: " << node.port << "\n";
    } else {
        std::istringstream stream(node.rawYaml);
        std::string line;
        size_t minIndent = (size_t)-1;
        std::vector<std::string> lines;
        while (std::getline(stream, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            size_t firstNonSpace = line.find_first_not_of(" \t");
            if (firstNonSpace != std::string::npos) {
                if (firstNonSpace < minIndent) minIndent = firstNonSpace;
            }
            lines.push_back(line);
        }
        if (minIndent == (size_t)-1) minIndent = 0;

        for (const auto& l : lines) {
            size_t firstNonSpace = l.find_first_not_of(" \t");
            if (firstNonSpace == std::string::npos) {
                oss << "\n";
            } else {
                size_t trimCount = (firstNonSpace >= minIndent) ? minIndent : firstNonSpace;
                oss << "  " << l.substr(trimCount) << "\n";
            }
        }
    }
    
    std::string safeNodeName = std::regex_replace(node.name, std::regex(R"(")"), "\\\"");
    oss << "\n";
    oss << "proxy-groups:\n";
    oss << "  - name: PROXY\n";
    oss << "    type: select\n";
    oss << "    proxies:\n";
    oss << "      - \"" << safeNodeName << "\"\n";
    oss << "  - name: GLOBAL\n";
    oss << "    type: select\n";
    oss << "    proxies:\n";
    oss << "      - \"" << safeNodeName << "\"\n";
    oss << "\n";
    oss << "rules:\n";
    oss << "  - MATCH,PROXY\n";
    
    return oss.str();
}

bool ClashManager::MatchFilterRule(const std::string& text, const std::string& rule) {
    if (rule.empty()) return false;
    
    // 转为小写以实现大小写无关匹配
    std::string textLower = text;
    std::transform(textLower.begin(), textLower.end(), textLower.begin(), [](unsigned char c){ return (char)std::tolower(c); });
    
    // 标准化 OR 分隔符：将 "||", " 或 ", "或", "\r\n", "\n" 均替换为 "|"
    std::string normRule = rule;
    
    auto replaceAll = [](std::string& str, const std::string& from, const std::string& to) {
        if (from.empty()) return;
        size_t pos = 0;
        while ((pos = str.find(from, pos)) != std::string::npos) {
            str.replace(pos, from.length(), to);
            pos += to.length();
        }
    };
    
    replaceAll(normRule, "||", "|");
    replaceAll(normRule, " 或 ", "|");
    replaceAll(normRule, "或", "|");
    replaceAll(normRule, "\r\n", "|");
    replaceAll(normRule, "\n", "|");
    replaceAll(normRule, "\r", "|");
    
    std::istringstream stream(normRule);
    std::string branch;
    while (std::getline(stream, branch, '|')) {
        // 去除首尾空白
        while (!branch.empty() && isspace((unsigned char)branch.front())) branch.erase(branch.begin());
        while (!branch.empty() && isspace((unsigned char)branch.back())) branch.pop_back();
        if (branch.empty()) continue;
        
        // 分割 AND 关键词: "&", "&&", "+"
        replaceAll(branch, "&&", "&");
        replaceAll(branch, "+", "&");
        
        std::istringstream bStream(branch);
        std::string term;
        bool allMatched = true;
        bool hasTerm = false;
        
        while (std::getline(bStream, term, '&')) {
            while (!term.empty() && isspace((unsigned char)term.front())) term.erase(term.begin());
            while (!term.empty() && isspace((unsigned char)term.back())) term.pop_back();
            if (term.empty()) continue;
            
            hasTerm = true;
            std::string termLower = term;
            std::transform(termLower.begin(), termLower.end(), termLower.begin(), [](unsigned char c){ return (char)std::tolower(c); });
            
            if (textLower.find(termLower) == std::string::npos) {
                allMatched = false;
                break;
            }
        }
        
        if (hasTerm && allMatched) {
            return true;
        }
    }
    
    return false;
}

bool ClashManager::ShouldKeepNode(const ClashNode& node, const std::string& includeFilter, const std::string& excludeFilter) {
    std::string combinedInfo = node.name + " " + node.server;
    
    // 检查排除规则
    if (!excludeFilter.empty()) {
        if (MatchFilterRule(combinedInfo, excludeFilter)) {
            return false;
        }
    }
    
    // 检查筛选规则
    if (!includeFilter.empty()) {
        if (!MatchFilterRule(combinedInfo, includeFilter)) {
            return false;
        }
    }
    
    return true;
}

std::vector<ClashNode> ClashManager::FilterAndDeduplicateNodes(const std::vector<ClashNode>& nodes, const std::string& includeFilter, const std::string& excludeFilter) {
    std::vector<ClashNode> result;
    std::set<std::string> seenEndpoints;
    std::set<std::string> seenNames;
    
    for (const auto& node : nodes) {
        if (!ShouldKeepNode(node, includeFilter, excludeFilter)) {
            continue;
        }
        
        // 消重检查：相同节点名，或相同 server+port
        std::string endpointKey = node.server + ":" + std::to_string(node.port);
        std::string nameKey = node.name;
        
        if (!nameKey.empty() && seenNames.count(nameKey)) {
            continue; // 跳过同名节点
        }
        if (!node.server.empty() && node.port > 0 && seenEndpoints.count(endpointKey)) {
            continue; // 跳过同服务器地址和端口的重复节点
        }
        
        if (!nameKey.empty()) seenNames.insert(nameKey);
        if (!node.server.empty() && node.port > 0) seenEndpoints.insert(endpointKey);
        
        result.push_back(node);
    }
    
    return result;
}

ClashManager::SubscriptionCycleInfo ClashManager::CalculateCycleInfo(const std::string& resetStartDateStr, int resetCycleDays, int lastResetCycle, const std::string& createdAt) {
    SubscriptionCycleInfo info;
    bool isNaturalMonth = (resetCycleDays <= 0 || resetCycleDays == 30); // 0 或 30 默认按当月自然月天数计算
    
    std::string startStr = resetStartDateStr;
    if (startStr.empty() || startStr.length() < 10) {
        if (!createdAt.empty() && createdAt.length() >= 10) {
            startStr = createdAt.substr(0, 10);
        } else {
            startStr = Utils::GetCurrentDate().substr(0, 10);
        }
    }
    
    int startY = 2026, startM = 1, startD = 1;
    if (sscanf_s(startStr.c_str(), "%d-%d-%d", &startY, &startM, &startD) < 3) {
        startY = 2026; startM = 1; startD = 1;
    }
    
    time_t nowTime = time(nullptr);
    info.isNaturalMonth = isNaturalMonth;

    if (isNaturalMonth) {
        // ========== 当月自然月天数计算逻辑 (精确支持28/29/30/31天与闰年/月末对齐) ==========
        int anchorDay = startD; // 起始基准日 (如 17 号、1 号或 31 号)

        auto GetDaysInMonth = [](int year, int month) -> int {
            static const int days[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
            if (month < 1 || month > 12) return 30;
            if (month == 2) {
                bool isLeap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
                if (isLeap) return 29;
            }
            return days[month - 1];
        };

        auto NextMonth = [](int& y, int& m) {
            if (m >= 12) {
                y++;
                m = 1;
            } else {
                m++;
            }
        };

        auto MakeDate = [](int y, int m, int d) -> time_t {
            std::tm tmVal = {};
            tmVal.tm_year = y - 1900;
            tmVal.tm_mon = m - 1;
            tmVal.tm_mday = d;
            tmVal.tm_hour = 0;
            tmVal.tm_min = 0;
            tmVal.tm_sec = 0;
            tmVal.tm_isdst = -1;
            return std::mktime(&tmVal);
        };

        auto FormatDate = [](int y, int m, int d) -> std::string {
            char buf[32];
            sprintf_s(buf, "%04d-%02d-%02d", y, m, d);
            return buf;
        };

        int curY = startY;
        int curM = startM;
        int curD = (std::min)(anchorDay, GetDaysInMonth(curY, curM));
        time_t tCur = MakeDate(curY, curM, curD);

        int nextY = curY;
        int nextM = curM;
        NextMonth(nextY, nextM);
        int nextD = (std::min)(anchorDay, GetDaysInMonth(nextY, nextM));
        time_t tNext = MakeDate(nextY, nextM, nextD);

        int curCycle = 0;
        if (nowTime < tCur) {
            // 当前时间早于起始时间
            int totalDays = (int)((tNext - tCur + 43200) / 86400);
            if (totalDays <= 0) totalDays = GetDaysInMonth(curY, curM);
            info.curCycle = 0;
            info.daysPassed = 0;
            info.cycleTotalDays = totalDays;
            info.daysRemaining = totalDays;
            info.cyclePercent = 0.0;
            info.curCycleStart = FormatDate(curY, curM, curD);
            info.nextResetDate = FormatDate(nextY, nextM, nextD);
            info.needReset = false;
            return info;
        }

        // 当前时间 >= tCur，逐月向前推进直到包含当前时间
        while (nowTime >= tNext && curCycle < 1200) {
            curCycle++;
            curY = nextY;
            curM = nextM;
            curD = nextD;
            tCur = tNext;

            NextMonth(nextY, nextM);
            nextD = (std::min)(anchorDay, GetDaysInMonth(nextY, nextM));
            tNext = MakeDate(nextY, nextM, nextD);
        }

        int cycleTotalDays = (int)((tNext - tCur + 43200) / 86400);
        if (cycleTotalDays <= 0) cycleTotalDays = GetDaysInMonth(curY, curM);

        double elapsedSec = std::difftime(nowTime, tCur);
        int daysPassed = (int)(elapsedSec / 86400.0);
        if (daysPassed < 0) daysPassed = 0;
        if (daysPassed > cycleTotalDays) daysPassed = cycleTotalDays;

        int daysRemaining = (std::max)(0, cycleTotalDays - daysPassed);

        double totalSec = std::difftime(tNext, tCur);
        double pct = (totalSec > 0) ? (elapsedSec / totalSec) * 100.0 : 0.0;
        if (pct < 0.0) pct = 0.0;
        if (pct > 100.0) pct = 100.0;

        info.curCycle = curCycle;
        info.daysPassed = daysPassed;
        info.daysRemaining = daysRemaining;
        info.cycleTotalDays = cycleTotalDays;
        info.cyclePercent = pct;
        info.curCycleStart = FormatDate(curY, curM, curD);
        info.nextResetDate = FormatDate(nextY, nextM, nextD);
        if (curCycle > lastResetCycle) {
            info.needReset = true;
        }
        return info;
    }

    // ========== 自定义固定天数计算逻辑 (resetCycleDays > 0) ==========
    std::tm startTm = {};
    startTm.tm_year = startY - 1900;
    startTm.tm_mon = startM - 1;
    startTm.tm_mday = startD;
    startTm.tm_hour = 0;
    startTm.tm_min = 0;
    startTm.tm_sec = 0;
    startTm.tm_isdst = -1;
    time_t startTime = std::mktime(&startTm);
    
    double diffSec = std::difftime(nowTime, startTime);
    int64_t totalDiffDays = 0;
    if (diffSec > 0) {
        totalDiffDays = (int64_t)(diffSec / 86400.0);
    }
    
    int curCycle = 0;
    int daysPassed = 0;
    if (totalDiffDays > 0) {
        curCycle = (int)(totalDiffDays / resetCycleDays);
        daysPassed = (int)(totalDiffDays % resetCycleDays);
    }
    
    info.curCycle = curCycle;
    info.daysPassed = daysPassed;
    info.cycleTotalDays = resetCycleDays;
    info.daysRemaining = (std::max)(0, resetCycleDays - daysPassed);
    info.cyclePercent = (std::min)(100.0, (std::max)(0.0, ((double)daysPassed / (double)resetCycleDays) * 100.0));
    
    // 当前周期的开始日期和重置截止日期
    time_t cycleStartTime = startTime + (time_t)curCycle * (time_t)resetCycleDays * 86400;
    time_t cycleEndTime = cycleStartTime + (time_t)resetCycleDays * 86400;
    
    std::tm cStartTm = {}, cEndTm = {};
    localtime_s(&cStartTm, &cycleStartTime);
    localtime_s(&cEndTm, &cycleEndTime);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d", &cStartTm);
    info.curCycleStart = buf;
    std::strftime(buf, sizeof(buf), "%Y-%m-%d", &cEndTm);
    info.nextResetDate = buf;
    
    if (curCycle > lastResetCycle) {
        info.needReset = true;
    }
    
    return info;
}

int ClashManager::RefreshSubscription(int subscriptionId) {
    // 获取订阅信息
    ClashSubscription sub;
    if (!Database::Instance().GetSubscription(subscriptionId, sub)) {
        Utils::LogError("Subscription not found: " + std::to_string(subscriptionId));
        return -1;
    }
    
    // 下载订阅内容并获取最新流量与有效期信息
    SubscriptionUserInfo userInfo;
    std::string content = DownloadSubscription(sub.url, &userInfo);
    if (content.empty()) {
        Utils::LogError("Failed to download subscription: " + sub.name);
        return -1;
    }
    
    // 解析原始节点
    auto rawNodes = ParseSubscriptionNodes(content);
    if (rawNodes.empty()) {
        Utils::LogError("No nodes found in subscription: " + sub.name);
        return -1;
    }

    // 应用筛选规则、排除规则与消重
    auto newNodes = FilterAndDeduplicateNodes(rawNodes, sub.includeFilter, sub.excludeFilter);
    Utils::Log("Subscription '" + sub.name + "': filtered from " + std::to_string(rawNodes.size()) + " to " + std::to_string(newNodes.size()) + " nodes");
    
    // 更新订阅缓存及流量/有效期信息
    sub.rawContent = content;
    if (userInfo.uploadBytes > 0 || userInfo.downloadBytes > 0 || userInfo.totalBytes > 0) {
        sub.uploadBytes = userInfo.uploadBytes;
        sub.downloadBytes = userInfo.downloadBytes;
        sub.totalBytes = userInfo.totalBytes;
    }
    if (!userInfo.expireTime.empty()) {
        sub.expireTime = userInfo.expireTime;
    }
    if (!userInfo.websiteUrl.empty()) {
        sub.websiteUrl = userInfo.websiteUrl;
    }

    // 检查流量起始日期与重置周期：优先采用订阅返回的真实起始日期
    if (!userInfo.startDate.empty()) {
        sub.resetStartDate = userInfo.startDate;
    } else if (sub.resetStartDate.empty()) {
        sub.resetStartDate = sub.createdAt.empty() ? Utils::GetCurrentDate().substr(0, 10) : sub.createdAt.substr(0, 10);
    }
    if (sub.resetCycleDays == 30 || sub.resetCycleDays < 0) {
        sub.resetCycleDays = 0; // 0 表示按当月自然月天数
    }

    // 更新 lastUpdated 时间戳
    auto now = std::chrono::system_clock::now();
    auto nowTime = std::chrono::system_clock::to_time_t(now);
    char timeBuf[64];
    std::tm tmBuf = {};
    localtime_s(&tmBuf, &nowTime);
    std::strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", &tmBuf);
    sub.lastUpdated = timeBuf;
    Database::Instance().UpdateSubscription(sub);
    
    // 建立原有服务器/节点的分组记忆映射表
    auto existingSubPorts = Database::Instance().GetPortsBySubscriptionId(subscriptionId);
    auto allPorts = Database::Instance().GetAllProxyPorts();
    
    std::map<std::string, std::string> serverToGroup;
    std::map<std::string, std::string> nameToGroup;

    // 先存全库已有节点分组
    for (const auto& p : allPorts) {
        if (!p.groupName.empty()) {
            std::string sKey = p.upstreamHost + ":" + std::to_string(p.upstreamPort);
            serverToGroup[sKey] = p.groupName;
            if (!p.clashNodeName.empty()) {
                nameToGroup[p.clashNodeName] = p.groupName;
            }
        }
    }
    // 再用当前订阅的已有节点分组覆盖（以本订阅当前设置为最高优先级）
    for (const auto& p : existingSubPorts) {
        if (!p.groupName.empty()) {
            std::string sKey = p.upstreamHost + ":" + std::to_string(p.upstreamPort);
            serverToGroup[sKey] = p.groupName;
            if (!p.clashNodeName.empty()) {
                nameToGroup[p.clashNodeName] = p.groupName;
            }
        }
    }

    std::set<int> keepPortIds;
    std::set<size_t> matchedNewNodeIndices;
    int updated = 0;
    
    for (auto& port : existingSubPorts) {
        // 在新节点列表中查找匹配的节点：优先名称相同，其次相同服务器(host:port)
        int matchedIdx = -1;
        // 1. 同名匹配
        for (size_t i = 0; i < newNodes.size(); ++i) {
            if (matchedNewNodeIndices.count(i) > 0) continue;
            const auto& node = newNodes[i];
            bool isNameMatch = (!port.clashNodeName.empty() && node.name == port.clashNodeName) ||
                               (port.clashNodeName.empty() && !node.name.empty() && 
                                (port.description == node.name || port.description.find(node.name) != std::string::npos));
            if (isNameMatch) {
                matchedIdx = (int)i;
                break;
            }
        }
        // 2. 同服务器匹配 (若节点名称微调但服务器相同)
        if (matchedIdx < 0) {
            for (size_t i = 0; i < newNodes.size(); ++i) {
                if (matchedNewNodeIndices.count(i) > 0) continue;
                const auto& node = newNodes[i];
                if (!node.server.empty() && !port.upstreamHost.empty() &&
                    port.upstreamHost == node.server && port.upstreamPort == node.port) {
                    matchedIdx = (int)i;
                    break;
                }
            }
        }

        if (matchedIdx >= 0) {
            const auto& node = newNodes[matchedIdx];
            matchedNewNodeIndices.insert((size_t)matchedIdx);
            keepPortIds.insert(port.id);
            
            // 更新配置，保留原有分组
            int localPort = GetLocalSocksPort(port.id);
            std::string newConfig = GenerateNodeConfig(node, localPort > 0 ? localPort : 30000);
            
            port.clashConfig = newConfig;
            port.upstreamHost = node.server;
            port.upstreamPort = node.port;
            port.clashNodeName = node.name;
            port.description = (sub.name.empty() ? "" : (sub.name + " - ")) + node.name;
            
            // 确保保留原有分组；若之前为空，则从记忆映射表恢复或推导
            if (port.groupName.empty()) {
                std::string sKey = node.server + ":" + std::to_string(node.port);
                if (serverToGroup.find(sKey) != serverToGroup.end() && !serverToGroup[sKey].empty()) {
                    port.groupName = serverToGroup[sKey];
                } else if (nameToGroup.find(node.name) != nameToGroup.end() && !nameToGroup[node.name].empty()) {
                    port.groupName = nameToGroup[node.name];
                } else {
                    port.groupName = Database::InferNodeGroup(node.name, port.description);
                }
            }

            Database::Instance().UpdateProxyPort(port);
            updated++;
        } else {
            Database::Instance().DeleteProxyPort(port.id);
        }
    }

    // 检查是否有未匹配的新节点并添加
    for (size_t i = 0; i < newNodes.size(); ++i) {
        if (matchedNewNodeIndices.count(i) > 0) continue;
        const auto& node = newNodes[i];

        bool found = false;
        for (int keptId : keepPortIds) {
            ProxyPort kp;
            if (Database::Instance().GetProxyPort(keptId, kp)) {
                if (kp.clashNodeName == node.name || 
                    (!node.server.empty() && kp.upstreamHost == node.server && kp.upstreamPort == node.port)) {
                    found = true;
                    break;
                }
            }
        }
        if (!found) {
            ProxyPort p;
            p.upstreamType = "clash";
            p.description = (sub.name.empty() ? "" : (sub.name + " - ")) + node.name;
            p.upstreamHost = node.server;
            p.upstreamPort = node.port;
            p.clashNodeName = node.name;

            // 原有服务器优先保留原有分组
            std::string sKey = node.server + ":" + std::to_string(node.port);
            if (serverToGroup.find(sKey) != serverToGroup.end() && !serverToGroup[sKey].empty()) {
                p.groupName = serverToGroup[sKey];
            } else if (nameToGroup.find(node.name) != nameToGroup.end() && !nameToGroup[node.name].empty()) {
                p.groupName = nameToGroup[node.name];
            } else {
                p.groupName = Database::InferNodeGroup(node.name, p.description);
            }

            p.clashConfig = GenerateNodeConfig(node, 0);
            p.listenPort = 0;
            p.enabled = true;
            p.autoCheck = true;
            p.clashSubscriptionId = subscriptionId;
            if (Database::Instance().AddProxyPort(p)) {
                updated++;
            }
        }
    }
    
    // 全局消重检查，确保无任何重复残留
    Database::Instance().DeduplicateProxyPorts();
    
    // 统一重载单一 Mihomo 实例配置
    StartOrReloadUnified();
    
    Utils::Log("Subscription '" + sub.name + "' refreshed, " + std::to_string(updated) + " ports updated/added");
    return updated;
}

void ClashManager::StartAutoUpdate() {
    if (autoUpdateRunning_) return;
    autoUpdateRunning_ = true;
    autoUpdateThread_ = std::thread(&ClashManager::AutoUpdateLoop, this);
}

void ClashManager::StopAutoUpdate() {
    autoUpdateRunning_ = false;
    if (autoUpdateThread_.joinable()) {
        autoUpdateThread_.join();
    }
}

void ClashManager::AutoUpdateLoop() {
    Utils::Log("Clash subscription auto-update thread started (1 hour interval)");
    
    while (autoUpdateRunning_) {
        // 每 60 秒检查一次是否有距上次更新已满 1 小时的订阅
        for (int i = 0; i < 60 && autoUpdateRunning_; i++) {
            Sleep(1000);
        }
        if (!autoUpdateRunning_) break;
        
        auto now = std::chrono::system_clock::now();
        auto nowTime = std::chrono::system_clock::to_time_t(now);
        
        // 遍历所有订阅，如果距上次更新超过 1 小时（3600秒）或未曾更新过，则自动执行后台更新
        auto subs = Database::Instance().GetAllSubscriptions();
        for (const auto& sub : subs) {
            if (!autoUpdateRunning_) break;
            
            bool needUpdate = false;
            if (sub.lastUpdated.empty()) {
                needUpdate = true;
            } else {
                struct tm lastTm = {};
                int parsed = sscanf(sub.lastUpdated.c_str(), "%d-%d-%d %d:%d:%d", 
                                    &lastTm.tm_year, &lastTm.tm_mon, &lastTm.tm_mday,
                                    &lastTm.tm_hour, &lastTm.tm_min, &lastTm.tm_sec);
                if (parsed >= 3) {
                    lastTm.tm_year -= 1900;
                    lastTm.tm_mon -= 1;
                    time_t lastTime = std::mktime(&lastTm);
                    double diffSec = std::difftime(nowTime, lastTime);
                    // 超过 1 小时自动更新
                    if (diffSec >= 3600.0) {
                        needUpdate = true;
                    }
                } else {
                    needUpdate = true;
                }
            }
            
            if (needUpdate) {
                Utils::Log("Auto-updating subscription (1 hour cycle): " + sub.name);
                RefreshSubscription(sub.id);
            }
        }
    }
    
    Utils::Log("Clash subscription auto-update thread stopped");
}

std::vector<DWORD> ClashManager::GetAllProcessIds() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<DWORD> pids;
    if (unifiedProcessId_ != 0 && IsUnifiedAliveInternal()) {
        pids.push_back(unifiedProcessId_);
    }
    return pids;
}
