#include "ClashManager.h"
#include "Database.h"
#include "Utils.h"
#include "json.hpp"
#include <iostream>
#include <sstream>
#include <fstream>
#include <regex>
#include <chrono>
#include <ctime>
#include <set>
#include <algorithm>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <cstring>
#include <cmath>

ClashManager& ClashManager::Instance() {
    static ClashManager instance;
    return instance;
}

ClashManager::ClashManager() {
    Initialize();
}

ClashManager::~ClashManager() {
    StopAll();
}

bool ClashManager::Initialize() {
    std::vector<std::string> candidates = {
        "/usr/bin/mihomo",
        "/etc/openclash/clash",
        "/etc/openclash/core/clash_meta",
        "/etc/openclash/core/clash",
        "/etc/openclash/core/clash_tun",
        "/usr/share/proxyrelay/bin/mihomo",
        "/usr/bin/clash",
        "/usr/local/bin/mihomo",
        "./mihomo"
    };

    auto isExecutableValid = [](const std::string& p) {
        if (access(p.c_str(), X_OK) != 0) return false;
        std::string ver = Utils::Trim(Utils::ExecCmd("\"" + p + "\" -v 2>&1"));
        return !ver.empty() && ver.find("microarchitecture") == std::string::npos &&
               ver.find("Illegal") == std::string::npos && ver.find("not found") == std::string::npos;
    };

    for (const auto& path : candidates) {
        if (isExecutableValid(path)) {
            clashPath_ = path;
            std::cout << "[ClashManager] Found working Clash core: " << clashPath_ << std::endl;
            return true;
        }
    }

    // PATH 探测 (mihomo / clash)
    std::string whichMihomo = Utils::Trim(Utils::ExecCmd("which mihomo 2>/dev/null"));
    if (!whichMihomo.empty() && isExecutableValid(whichMihomo)) {
        clashPath_ = whichMihomo;
        std::cout << "[ClashManager] Found working Clash core via PATH: " << clashPath_ << std::endl;
        return true;
    }

    std::string whichClash = Utils::Trim(Utils::ExecCmd("which clash 2>/dev/null"));
    if (!whichClash.empty() && isExecutableValid(whichClash)) {
        clashPath_ = whichClash;
        std::cout << "[ClashManager] Found working Clash core via PATH: " << clashPath_ << std::endl;
        return true;
    }

    std::cout << "[ClashManager] Warning: No mihomo/clash executable found." << std::endl;
    return false;
}

int ClashManager::FindAvailablePort() {
    for (int port = 17001; port < 18000; ++port) {
        // 1. 确保该端口未被当前记录的任何核心实例分配
        bool inUse = false;
        for (const auto& kv : processes_) {
            if (kv.second.localPort == port) {
                inUse = true;
                break;
            }
        }
        if (inUse) continue;

        // 2. 检查 TCP 端口是否被占用 (探测时不开启 SO_REUSEADDR 避免与正在使用/关闭中的端口冲突)
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) continue;

        sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port);

        if (bind(s, (sockaddr*)&addr, sizeof(addr)) != 0) {
            close(s);
            continue;
        }
        close(s);

        // 3. 检查 UDP 端口是否可绑定 (Mihomo mixed-port 需同时监听 UDP)
        int u = socket(AF_INET, SOCK_DGRAM, 0);
        if (u >= 0) {
            if (bind(u, (sockaddr*)&addr, sizeof(addr)) != 0) {
                close(u);
                continue;
            }
            close(u);
        }

        return port;
    }
    return 0;
}

int ClashManager::StartClash(int portId, const std::string& configYaml) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    auto it = processes_.find(portId);
    if (it != processes_.end()) {
        if (IsRunning(portId)) {
            return it->second.localPort;
        }
        StopClash(portId);
    }

    if (clashPath_.empty()) {
        Initialize();
        if (clashPath_.empty()) {
            std::cerr << "[ClashManager] Error: clash executable not found" << std::endl;
            return 0;
        }
    }

    int localPort = FindAvailablePort();
    if (localPort == 0) {
        std::cerr << "[ClashManager] Error: failed to allocate local port for clash" << std::endl;
        return 0;
    }

    std::string processedYaml = configYaml;
    // 清除可能存在的全局冲突项
    processedYaml = std::regex_replace(processedYaml, std::regex(R"((^|\r?\n)\s*(mixed-port|port|socks-port|redir-port|tproxy-port|allow-lan|bind-address|mode|log-level|external-controller|routing-mark|ipv6)\s*:[^\r\n]*)"), "");

    std::ostringstream oss;
    oss << "bind-address: \"127.0.0.1\"\n";
    oss << "mixed-port: " << localPort << "\n";
    oss << "port: 0\n";
    oss << "socks-port: 0\n";
    oss << "redir-port: 0\n";
    oss << "tproxy-port: 0\n";
    oss << "allow-lan: false\n";
    oss << "mode: rule\n";
    oss << "log-level: error\n";
    oss << "external-controller: \"\"\n";
    oss << "routing-mark: 255\n";
    oss << "ipv6: false\n";
    if (processedYaml.find("\ndns:") == std::string::npos && processedYaml.rfind("dns:", 0) != 0) {
        oss << "dns:\n";
        oss << "  enable: true\n";
        oss << "  ipv6: false\n";
        oss << "  default-nameserver:\n";
        oss << "    - 223.5.5.5\n";
        oss << "    - 119.29.29.29\n";
        oss << "  nameserver:\n";
        oss << "    - 223.5.5.5\n";
        oss << "    - 119.29.29.29\n";
        oss << "  proxy-server-nameserver:\n";
        oss << "    - 223.5.5.5\n";
        oss << "    - 119.29.29.29\n";
    }
    oss << processedYaml;

    mkdir("/tmp/proxyrelay", 0755);
    std::string configPath = "/tmp/proxyrelay/clash_" + std::to_string(portId) + ".yaml";
    std::ofstream out(configPath);
    if (!out.is_open()) {
        std::cerr << "[ClashManager] Failed to write config: " << configPath << std::endl;
        return 0;
    }
    out << oss.str();
    out.close();

    pid_t pid = fork();
    if (pid < 0) {
        std::cerr << "[ClashManager] fork failed" << std::endl;
        unlink(configPath.c_str());
        return 0;
    } else if (pid == 0) {
        // Child process
        int devNull = open("/dev/null", O_RDWR);
        if (devNull >= 0) {
            dup2(devNull, STDIN_FILENO);
            dup2(devNull, STDOUT_FILENO);
            dup2(devNull, STDERR_FILENO);
            close(devNull);
        }
        // 关闭从父进程继承的所有文件描述符，防止子进程泄漏监听 socket (如 12345 端口)
        for (int fd = 3; fd < 1024; ++fd) {
            close(fd);
        }
        execl(clashPath_.c_str(), clashPath_.c_str(), "-d", "/tmp/proxyrelay", "-f", configPath.c_str(), nullptr);
        _exit(1);
    }

    // 等待本地 SOCKS5 端口监听就绪（最多 5000ms = 100 * 50ms）
    bool portReady = false;
    for (int attempt = 0; attempt < 100; ++attempt) {
        int status;
        pid_t wr = waitpid(pid, &status, WNOHANG);
        if (wr > 0 || (wr == -1 && errno == ECHILD)) {
            break; // 进程已意外退出
        }
        int checkSock = socket(AF_INET, SOCK_STREAM, 0);
        if (checkSock >= 0) {
            sockaddr_in testAddr = {};
            testAddr.sin_family = AF_INET;
            testAddr.sin_port = htons(localPort);
            inet_pton(AF_INET, "127.0.0.1", &testAddr.sin_addr);

            int flags = fcntl(checkSock, F_GETFL, 0);
            fcntl(checkSock, F_SETFL, flags | O_NONBLOCK);

            connect(checkSock, (sockaddr*)&testAddr, sizeof(testAddr));
            fd_set writeFds;
            FD_ZERO(&writeFds);
            FD_SET(checkSock, &writeFds);
            timeval tv = {0, 50000}; // 50ms
            if (select(checkSock + 1, nullptr, &writeFds, nullptr, &tv) > 0) {
                int optErr = 0;
                socklen_t optLen = sizeof(optErr);
                if (getsockopt(checkSock, SOL_SOCKET, SO_ERROR, &optErr, &optLen) == 0 && optErr == 0) {
                    portReady = true;
                    close(checkSock);
                    break;
                }
            }
            close(checkSock);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    if (!portReady) {
        std::cerr << "[ClashManager] Error: mihomo port " << localPort << " failed to listen" << std::endl;
        kill(pid, SIGKILL);
        waitpid(pid, nullptr, 0);
        unlink(configPath.c_str());
        return 0;
    }

    processes_[portId] = { pid, localPort };
    std::cout << "[ClashManager] Mihomo started for port " << portId << ", local mixed-port: " << localPort << ", PID: " << pid << std::endl;
    return localPort;
}

void ClashManager::StopClash(int portId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto it = processes_.find(portId);
    if (it != processes_.end()) {
        pid_t pid = it->second.pid;
        if (pid > 0) {
            kill(pid, SIGTERM);
            for (int i = 0; i < 10; ++i) {
                int status;
                pid_t wr = waitpid(pid, &status, WNOHANG);
                if (wr > 0 || (wr == -1 && errno == ECHILD)) {
                    pid = 0;
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            }
            if (pid > 0) {
                kill(pid, SIGKILL);
                waitpid(pid, nullptr, 0);
            }
        }
        std::string configPath = "/tmp/proxyrelay/clash_" + std::to_string(portId) + ".yaml";
        unlink(configPath.c_str());
        processes_.erase(it);
    }
}

void ClashManager::StopAll() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    for (auto& kv : processes_) {
        pid_t pid = kv.second.pid;
        if (pid > 0) {
            kill(pid, SIGTERM);
            for (int i = 0; i < 10; ++i) {
                int status;
                pid_t wr = waitpid(pid, &status, WNOHANG);
                if (wr > 0 || (wr == -1 && errno == ECHILD)) {
                    pid = 0;
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            }
            if (pid > 0) {
                kill(pid, SIGKILL);
                waitpid(pid, nullptr, 0);
            }
        }
        std::string configPath = "/tmp/proxyrelay/clash_" + std::to_string(kv.first) + ".yaml";
        unlink(configPath.c_str());
    }
    processes_.clear();
}

int ClashManager::GetLocalSocksPort(int portId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto it = processes_.find(portId);
    if (it != processes_.end()) {
        if (!IsRunning(portId)) {
            StopClash(portId);
            return 0;
        }
        return it->second.localPort;
    }
    return 0;
}

bool ClashManager::IsRunning(int portId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto it = processes_.find(portId);
    if (it == processes_.end()) return false;
    pid_t pid = it->second.pid;
    if (pid <= 0) return false;

    // 检查是否已退出或成为僵尸进程
    int status;
    pid_t wr = waitpid(pid, &status, WNOHANG);
    if (wr > 0 || (wr == -1 && errno == ECHILD)) {
        return false;
    }
    if (kill(pid, 0) != 0) {
        return false;
    }

    // 探测本地 SOCKS5 端口是否还在正常监听响应
    int checkSock = socket(AF_INET, SOCK_STREAM, 0);
    if (checkSock < 0) return false;

    sockaddr_in testAddr = {};
    testAddr.sin_family = AF_INET;
    testAddr.sin_port = htons(it->second.localPort);
    inet_pton(AF_INET, "127.0.0.1", &testAddr.sin_addr);

    int flags = fcntl(checkSock, F_GETFL, 0);
    fcntl(checkSock, F_SETFL, flags | O_NONBLOCK);

    connect(checkSock, (sockaddr*)&testAddr, sizeof(testAddr));
    fd_set writeFds;
    FD_ZERO(&writeFds);
    FD_SET(checkSock, &writeFds);
    timeval tv = {0, 50000}; // 50ms
    bool portAlive = false;
    if (select(checkSock + 1, nullptr, &writeFds, nullptr, &tv) > 0) {
        int optErr = 0;
        socklen_t optLen = sizeof(optErr);
        if (getsockopt(checkSock, SOL_SOCKET, SO_ERROR, &optErr, &optLen) == 0 && optErr == 0) {
            portAlive = true;
        }
    }
    close(checkSock);
    return portAlive;
}

// ========== 订阅解析与处理 ==========

static std::string CleanYamlValue(const std::string& raw) {
    if (raw.empty()) return "";
    size_t s = raw.find_first_not_of(" \t\r\n");
    if (s == std::string::npos) return "";
    if (raw[s] == '"' || raw[s] == '\'') {
        char quote = raw[s];
        size_t e = s + 1;
        while (e < raw.size() && raw[e] != quote) {
            if (raw[e] == '\\') e += 2;
            else e++;
        }
        return raw.substr(s + 1, e - s - 1);
    }
    std::string val = raw.substr(s);
    size_t hashPos = val.find('#');
    if (hashPos != std::string::npos) {
        val = val.substr(0, hashPos);
    }
    size_t e = val.find_last_not_of(" \t\r\n,\"'");
    if (e == std::string::npos) return "";
    return val.substr(0, e + 1);
}

static void ParseFlowMapping(const std::string& flowStr, ClashNode& node) {
    size_t i = 0;
    size_t len = flowStr.size();
    while (i < len) {
        while (i < len && (flowStr[i] == ' ' || flowStr[i] == '\t' || flowStr[i] == ',' || flowStr[i] == '{' || flowStr[i] == '}')) {
            i++;
        }
        if (i >= len) break;
        
        size_t keyStart = i;
        while (i < len && flowStr[i] != ':' && flowStr[i] != ' ' && flowStr[i] != '\t' && flowStr[i] != '}' && flowStr[i] != ',') {
            i++;
        }
        std::string key = flowStr.substr(keyStart, i - keyStart);
        
        while (i < len && (flowStr[i] == ' ' || flowStr[i] == '\t')) i++;
        if (i < len && flowStr[i] == ':') i++;
        while (i < len && (flowStr[i] == ' ' || flowStr[i] == '\t')) i++;
        
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

static bool ParseProtocolLink(const std::string& line, ClashNode& node) {
    std::string s = Utils::Trim(line);
    if (s.empty()) return false;

    if (s.rfind("ss://", 0) == 0) {
        std::string rest = s.substr(5);
        std::string tag;
        size_t hashPos = rest.find('#');
        if (hashPos != std::string::npos) {
            tag = Utils::Trim(rest.substr(hashPos + 1));
            rest = rest.substr(0, hashPos);
        }
        std::string server, cipher, password;
        int port = 0;

        size_t atPos = rest.find('@');
        if (atPos != std::string::npos) {
            std::string userinfo = rest.substr(0, atPos);
            std::string hostport = rest.substr(atPos + 1);
            if (userinfo.find(':') == std::string::npos) {
                userinfo = Utils::Base64Decode(userinfo);
            }
            size_t uColon = userinfo.find(':');
            if (uColon != std::string::npos) {
                cipher = userinfo.substr(0, uColon);
                password = userinfo.substr(uColon + 1);
            }
            size_t hColon = hostport.rfind(':');
            if (hColon != std::string::npos) {
                server = hostport.substr(0, hColon);
                try { port = std::stoi(hostport.substr(hColon + 1)); } catch (...) {}
            }
        } else {
            std::string decoded = Utils::Base64Decode(rest);
            size_t at = decoded.find('@');
            if (at != std::string::npos) {
                std::string userinfo = decoded.substr(0, at);
                std::string hostport = decoded.substr(at + 1);
                size_t uColon = userinfo.find(':');
                if (uColon != std::string::npos) {
                    cipher = userinfo.substr(0, uColon);
                    password = userinfo.substr(uColon + 1);
                }
                size_t hColon = hostport.rfind(':');
                if (hColon != std::string::npos) {
                    server = hostport.substr(0, hColon);
                    try { port = std::stoi(hostport.substr(hColon + 1)); } catch (...) {}
                }
            }
        }

        if (!server.empty() && port > 0) {
            node.name = tag.empty() ? ("SS-" + server + ":" + std::to_string(port)) : tag;
            node.type = "ss";
            node.server = server;
            node.port = port;
            node.rawYaml = "  - name: \"" + node.name + "\"\n"
                           "    type: ss\n"
                           "    server: " + server + "\n"
                           "    port: " + std::to_string(port) + "\n"
                           "    cipher: " + (cipher.empty() ? "aes-256-gcm" : cipher) + "\n"
                           "    password: \"" + password + "\"\n"
                           "    udp: true\n";
            return true;
        }
    } else if (s.rfind("trojan://", 0) == 0) {
        std::string rest = s.substr(9);
        std::string tag;
        size_t hashPos = rest.find('#');
        if (hashPos != std::string::npos) {
            tag = Utils::Trim(rest.substr(hashPos + 1));
            rest = rest.substr(0, hashPos);
        }
        std::string query;
        size_t qPos = rest.find('?');
        if (qPos != std::string::npos) {
            query = rest.substr(qPos + 1);
            rest = rest.substr(0, qPos);
        }
        size_t atPos = rest.find('@');
        if (atPos != std::string::npos) {
            std::string password = rest.substr(0, atPos);
            std::string hostport = rest.substr(atPos + 1);
            size_t hColon = hostport.rfind(':');
            if (hColon != std::string::npos) {
                std::string server = hostport.substr(0, hColon);
                int port = 0;
                try { port = std::stoi(hostport.substr(hColon + 1)); } catch (...) {}
                std::string sni = server;
                size_t sniPos = query.find("sni=");
                if (sniPos != std::string::npos) {
                    sni = query.substr(sniPos + 4);
                    size_t amp = sni.find('&');
                    if (amp != std::string::npos) sni = sni.substr(0, amp);
                }
                node.name = tag.empty() ? ("Trojan-" + server + ":" + std::to_string(port)) : tag;
                node.type = "trojan";
                node.server = server;
                node.port = port;
                node.rawYaml = "  - name: \"" + node.name + "\"\n"
                               "    type: trojan\n"
                               "    server: " + server + "\n"
                               "    port: " + std::to_string(port) + "\n"
                               "    password: \"" + password + "\"\n"
                               "    sni: " + sni + "\n"
                               "    skip-cert-verify: true\n"
                               "    udp: true\n";
                return true;
            }
        }
    } else if (s.rfind("vmess://", 0) == 0) {
        std::string b64 = s.substr(8);
        std::string jsonStr = Utils::Base64Decode(b64);
        try {
            auto j = nlohmann::json::parse(jsonStr);
            node.name = j.value("ps", "");
            node.server = j.value("add", "");
            node.type = "vmess";
            if (j.contains("port")) {
                if (j["port"].is_number()) node.port = j["port"].get<int>();
                else if (j["port"].is_string()) {
                    try { node.port = std::stoi(j["port"].get<std::string>()); } catch (...) {}
                }
            }
            std::string uuid = j.value("id", "");
            int aid = 0;
            if (j.contains("aid")) {
                if (j["aid"].is_number()) aid = j["aid"].get<int>();
                else if (j["aid"].is_string()) {
                    try { aid = std::stoi(j["aid"].get<std::string>()); } catch (...) {}
                }
            }
            std::string cipher = j.value("scy", "auto");
            std::string net = j.value("net", "tcp");
            std::string tls = j.value("tls", "");
            std::string host = j.value("host", "");
            std::string path = j.value("path", "");
            std::string sni = j.value("sni", host);

            if (node.name.empty()) node.name = "VMess-" + node.server;
            std::ostringstream oss;
            oss << "  - name: \"" << node.name << "\"\n"
                << "    type: vmess\n"
                << "    server: " << node.server << "\n"
                << "    port: " << node.port << "\n"
                << "    uuid: " << uuid << "\n"
                << "    alterId: " << aid << "\n"
                << "    cipher: " << cipher << "\n"
                << "    udp: true\n";
            if (tls == "tls") {
                oss << "    tls: true\n";
                if (!sni.empty()) oss << "    servername: " << sni << "\n";
                oss << "    skip-cert-verify: true\n";
            }
            if (net == "ws") {
                oss << "    network: ws\n"
                    << "    ws-opts:\n"
                    << "      path: \"" << (path.empty() ? "/" : path) << "\"\n";
                if (!host.empty()) {
                    oss << "      headers:\n"
                        << "        Host: " << host << "\n";
                }
            }
            node.rawYaml = oss.str();
            return true;
        } catch (...) {}
    } else if (s.rfind("vless://", 0) == 0) {
        std::string rest = s.substr(8);
        std::string tag;
        size_t hashPos = rest.find('#');
        if (hashPos != std::string::npos) {
            tag = Utils::Trim(rest.substr(hashPos + 1));
            rest = rest.substr(0, hashPos);
        }
        std::string query;
        size_t qPos = rest.find('?');
        if (qPos != std::string::npos) {
            query = rest.substr(qPos + 1);
            rest = rest.substr(0, qPos);
        }
        size_t atPos = rest.find('@');
        if (atPos != std::string::npos) {
            std::string uuid = rest.substr(0, atPos);
            std::string hostport = rest.substr(atPos + 1);
            size_t hColon = hostport.rfind(':');
            if (hColon != std::string::npos) {
                std::string server = hostport.substr(0, hColon);
                int port = 0;
                try { port = std::stoi(hostport.substr(hColon + 1)); } catch (...) {}
                node.name = tag.empty() ? ("VLESS-" + server + ":" + std::to_string(port)) : tag;
                node.type = "vless";
                node.server = server;
                node.port = port;
                std::ostringstream oss;
                oss << "  - name: \"" << node.name << "\"\n"
                    << "    type: vless\n"
                    << "    server: " << server << "\n"
                    << "    port: " << port << "\n"
                    << "    uuid: " << uuid << "\n"
                    << "    udp: true\n";
                if (query.find("security=tls") != std::string::npos || query.find("security=reality") != std::string::npos) {
                    oss << "    tls: true\n    skip-cert-verify: true\n";
                }
                node.rawYaml = oss.str();
                return true;
            }
        }
    }
    return false;
}

std::vector<ClashNode> ClashManager::ParseSubscriptionNodes(const std::string& yamlContent) {
    std::vector<ClashNode> nodes;
    if (yamlContent.empty()) return nodes;
    
    std::string content = yamlContent;
    if (content.size() >= 3 && 
        (unsigned char)content[0] == 0xEF && 
        (unsigned char)content[1] == 0xBB && 
        (unsigned char)content[2] == 0xBF) {
        content = content.substr(3);
    }
    
    // 检查是否有直接或 Base64 编码的节点链接 (vmess://, ss://, trojan://, vless://)
    std::string testContent = content;
    if (testContent.find("proxies:") == std::string::npos && testContent.find("Proxy:") == std::string::npos) {
        std::string decoded = Utils::Base64Decode(testContent);
        if (decoded.find("vmess://") != std::string::npos || decoded.find("ss://") != std::string::npos ||
            decoded.find("trojan://") != std::string::npos || decoded.find("vless://") != std::string::npos) {
            testContent = decoded;
        }
    }
    if (testContent.find("vmess://") != std::string::npos || testContent.find("ss://") != std::string::npos ||
        testContent.find("trojan://") != std::string::npos || testContent.find("vless://") != std::string::npos) {
        std::istringstream lStream(testContent);
        std::string lLine;
        while (std::getline(lStream, lLine)) {
            ClashNode lNode;
            if (ParseProtocolLink(lLine, lNode)) {
                nodes.push_back(lNode);
            }
        }
        if (!nodes.empty()) {
            std::cout << "[ClashManager] Parsed " << nodes.size() << " protocol link nodes" << std::endl;
            return nodes;
        }
    }

    // 如果没有 proxies / Proxy / server，尝试 Base64 解密 YAML
    if (content.find("proxies:") == std::string::npos && 
        content.find("Proxy:") == std::string::npos &&
        content.find("server:") == std::string::npos) {
        std::string decoded = Utils::Base64Decode(content);
        if (decoded.find("proxies:") != std::string::npos || 
            decoded.find("Proxy:") != std::string::npos ||
            decoded.find("server:") != std::string::npos) {
            content = decoded;
        }
    }
    
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
            // 严格验证：节点必须有名称、非空服务器地址、有效端口(1-65535)，且类型不能是 policy group (select, url-test, fallback, load-balance, relay)
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
        if (!line.empty() && line.back() == '\r') line.pop_back();
        
        size_t firstNonSpace = line.find_first_not_of(" \t");
        if (firstNonSpace == std::string::npos) {
            if (hasNode) currentNodeYaml += line + "\n";
            continue;
        }
        
        if (line[firstNonSpace] == '#') continue;
        
        // 顶层键检测（必须无缩进 firstNonSpace == 0 且不是列表项 '-'）
        if (firstNonSpace == 0 && line[0] != '-') {
            std::string trimmedLine = line.substr(firstNonSpace);
            if (trimmedLine.rfind("proxies:", 0) == 0 || trimmedLine.rfind("Proxy:", 0) == 0) {
                flushNode();
                inProxies = true;
                continue;
            } else if (inProxies) {
                // 进入了下一个顶层 key (如 proxy-groups:, rules:, 等)
                flushNode();
                inProxies = false;
                continue;
            }
        }
        
        if (!inProxies) continue;
        
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
    std::cout << "[ClashManager] Parsed " << nodes.size() << " nodes from subscription" << std::endl;
    return nodes;
}

std::string ClashManager::GenerateNodeConfig(const ClashNode& node, int mixedPort) {
    std::ostringstream oss;
    oss << "bind-address: \"127.0.0.1\"\n";
    oss << "mixed-port: " << mixedPort << "\n";
    oss << "port: 0\n";
    oss << "socks-port: 0\n";
    oss << "redir-port: 0\n";
    oss << "tproxy-port: 0\n";
    oss << "allow-lan: false\n";
    oss << "mode: rule\n";
    oss << "log-level: error\n";
    oss << "external-controller: \"\"\n\n";
    oss << "proxies:\n";
    
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
    oss << "\nproxy-groups:\n";
    oss << "  - name: PROXY\n";
    oss << "    type: select\n";
    oss << "    proxies:\n";
    oss << "      - \"" << safeNodeName << "\"\n\n";
    oss << "rules:\n";
    oss << "  - MATCH,PROXY\n";
    
    return oss.str();
}

bool ClashManager::MatchFilterRule(const std::string& text, const std::string& rule) {
    if (rule.empty()) return true;
    
    std::string textLower = text;
    std::transform(textLower.begin(), textLower.end(), textLower.begin(), [](unsigned char c){ return (char)std::tolower(c); });
    
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
        while (!branch.empty() && isspace((unsigned char)branch.front())) branch.erase(branch.begin());
        while (!branch.empty() && isspace((unsigned char)branch.back())) branch.pop_back();
        if (branch.empty()) continue;
        
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
        
        if (hasTerm && allMatched) return true;
    }
    
    return false;
}

bool ClashManager::ShouldKeepNode(const ClashNode& node, const std::string& includeFilter, const std::string& excludeFilter) {
    std::string combinedInfo = node.name + " " + node.server;
    if (!excludeFilter.empty()) {
        if (MatchFilterRule(combinedInfo, excludeFilter)) return false;
    }
    if (!includeFilter.empty()) {
        if (!MatchFilterRule(combinedInfo, includeFilter)) return false;
    }
    return true;
}

std::vector<ClashNode> ClashManager::FilterAndDeduplicateNodes(const std::vector<ClashNode>& nodes, const std::string& includeFilter, const std::string& excludeFilter) {
    std::vector<ClashNode> result;
    std::set<std::string> seenEndpoints;
    std::set<std::string> seenNames;
    
    for (const auto& node : nodes) {
        if (!ShouldKeepNode(node, includeFilter, excludeFilter)) continue;
        
        std::string endpointKey = node.server + ":" + std::to_string(node.port);
        std::string nameKey = node.name;
        
        if (!nameKey.empty() && seenNames.count(nameKey)) continue;
        if (!node.server.empty() && node.port > 0 && seenEndpoints.count(endpointKey)) continue;
        
        if (!nameKey.empty()) seenNames.insert(nameKey);
        if (!node.server.empty() && node.port > 0) seenEndpoints.insert(endpointKey);
        
        result.push_back(node);
    }
    
    return result;
}

void ClashManager::ParseSubscriptionHeaders(const std::string& headers, SubscriptionUserInfo& info) {
    std::string lower = headers;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c){ return (char)std::tolower(c); });

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
                    localtime_r(&t, &tmBuf);
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
                    localtime_r(&t, &tmBuf);
                    char buf[32];
                    std::strftime(buf, sizeof(buf), "%Y-%m-%d", &tmBuf);
                    info.startDate = buf;
                }
            } catch (...) {}
        }
    }

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
                    if (sscanf(val.c_str(), "%d-%d-%d", &y, &mo, &d) == 3) {
                        char buf[32];
                        snprintf(buf, sizeof(buf), "%04d-%02d-%02d", y, mo, d);
                        info.startDate = buf;
                    }
                }
            }
        }
    }
}

void ClashManager::ParseSubscriptionContentUserInfo(const std::string& content, SubscriptionUserInfo& info) {
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
}

std::string ClashManager::DownloadSubscription(const std::string& url, SubscriptionUserInfo* outInfo) {
    std::cout << "[ClashManager] Downloading subscription: " << url << std::endl;
    std::string headFile = "/tmp/proxyrelay_sub_head_" + std::to_string(getpid()) + ".tmp";
    std::string bodyFile = "/tmp/proxyrelay_sub_body_" + std::to_string(getpid()) + ".tmp";

    std::string safeUrl;
    for (char c : url) {
        if (c == '"' || c == '$' || c == '`' || c == '\\') safeUrl += '\\';
        safeUrl += c;
    }

    // 采用标准兼容 clash.meta / clash-verge 的 UA 进行下载
    std::string cmd = "curl -s -L -k --max-time 25 "
                      "-A \"clash.meta/v1.19.2 (ProxyRelay/OpenWrt)\" "
                      "-H \"Accept: application/yaml, text/yaml, */*\" "
                      "-D \"" + headFile + "\" "
                      "\"" + safeUrl + "\" -o \"" + bodyFile + "\" 2>/dev/null";

    int ret = system(cmd.c_str());
    if (ret != 0) {
        std::string fallback = "wget -q --no-check-certificate --timeout=25 -U \"clash.meta/v1.19.2\" -O \"" + bodyFile + "\" \"" + safeUrl + "\" 2>/dev/null";
        int r = system(fallback.c_str());
        (void)r;
    }

    std::string result;
    std::ifstream bf(bodyFile, std::ios::binary);
    if (bf.is_open()) {
        result.assign((std::istreambuf_iterator<char>(bf)), std::istreambuf_iterator<char>());
        bf.close();
    }
    unlink(bodyFile.c_str());

    // 若直连下载失败或内容为空，尝试通过本地代理端口 (1080) 重试（适应节点订阅在境外或被阻断场景）
    if (result.empty()) {
        std::string proxyCmd = "curl -s -L -k --max-time 25 -x socks5h://127.0.0.1:1080 "
                              "-A \"clash.meta/v1.19.2 (ProxyRelay/OpenWrt)\" "
                              "-H \"Accept: application/yaml, text/yaml, */*\" "
                              "-D \"" + headFile + "\" "
                              "\"" + safeUrl + "\" -o \"" + bodyFile + "\" 2>/dev/null";
        int pr = system(proxyCmd.c_str());
        (void)pr;
        std::ifstream rbf(bodyFile, std::ios::binary);
        if (rbf.is_open()) {
            result.assign((std::istreambuf_iterator<char>(rbf)), std::istreambuf_iterator<char>());
            rbf.close();
        }
        unlink(bodyFile.c_str());
    }

    if (outInfo) {
        *outInfo = SubscriptionUserInfo();
        size_t protoPos = url.find("://");
        if (protoPos != std::string::npos) {
            size_t pathPos = url.find('/', protoPos + 3);
            outInfo->websiteUrl = (pathPos == std::string::npos) ? url : url.substr(0, pathPos);
        }

        std::ifstream hf(headFile);
        if (hf.is_open()) {
            std::string rawHeaders((std::istreambuf_iterator<char>(hf)), std::istreambuf_iterator<char>());
            hf.close();
            ParseSubscriptionHeaders(rawHeaders, *outInfo);
        }
        ParseSubscriptionContentUserInfo(result, *outInfo);
    }
    unlink(headFile.c_str());

    std::cout << "[ClashManager] Downloaded subscription size: " << result.size() << " bytes" << std::endl;
    return result;
}

ClashManager::SubscriptionCycleInfo ClashManager::CalculateCycleInfo(const std::string& resetStartDateStr, int resetCycleDays, int lastResetCycle, const std::string& createdAt) {
    SubscriptionCycleInfo info;
    bool isNaturalMonth = (resetCycleDays <= 0 || resetCycleDays == 30);
    
    std::string startStr = resetStartDateStr;
    if (startStr.empty() || startStr.length() < 10) {
        if (!createdAt.empty() && createdAt.length() >= 10) {
            startStr = createdAt.substr(0, 10);
        } else {
            startStr = Utils::GetCurrentDate().substr(0, 10);
        }
    }
    
    int startY = 2026, startM = 1, startD = 1;
    if (sscanf(startStr.c_str(), "%d-%d-%d", &startY, &startM, &startD) < 3) {
        startY = 2026; startM = 1; startD = 1;
    }
    
    time_t nowTime = time(nullptr);
    info.isNaturalMonth = isNaturalMonth;

    if (isNaturalMonth) {
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
            if (m >= 12) { y++; m = 1; }
            else { m++; }
        };

        auto MakeDate = [](int y, int m, int d) -> time_t {
            std::tm tmVal = {};
            tmVal.tm_year = y - 1900;
            tmVal.tm_mon = m - 1;
            tmVal.tm_mday = d;
            return std::mktime(&tmVal);
        };

        auto FormatDate = [](int y, int m, int d) -> std::string {
            char buf[32];
            snprintf(buf, sizeof(buf), "%04d-%02d-%02d", y, m, d);
            return buf;
        };

        int curY = startY;
        int curM = startM;
        int curD = std::min(startD, GetDaysInMonth(curY, curM));
        time_t tCur = MakeDate(curY, curM, curD);

        int nextY = curY;
        int nextM = curM;
        NextMonth(nextY, nextM);
        int nextD = std::min(startD, GetDaysInMonth(nextY, nextM));
        time_t tNext = MakeDate(nextY, nextM, nextD);

        int cycleIndex = 1;
        while (nowTime >= tNext) {
            curY = nextY;
            curM = nextM;
            curD = nextD;
            tCur = tNext;
            NextMonth(nextY, nextM);
            nextD = std::min(startD, GetDaysInMonth(nextY, nextM));
            tNext = MakeDate(nextY, nextM, nextD);
            cycleIndex++;
        }

        info.curCycle = cycleIndex;
        info.curCycleStart = FormatDate(curY, curM, curD);
        info.nextResetDate = FormatDate(nextY, nextM, nextD);

        double totalSecs = (double)(tNext - tCur);
        if (totalSecs <= 0) totalSecs = 86400 * 30;
        double passedSecs = (double)(nowTime - tCur);
        if (passedSecs < 0) passedSecs = 0;

        info.cycleTotalDays = (int)std::round(totalSecs / 86400.0);
        info.daysPassed = (int)(passedSecs / 86400.0);
        info.daysRemaining = std::max(0, info.cycleTotalDays - info.daysPassed);
        info.cyclePercent = std::min(100.0, std::max(0.0, (passedSecs / totalSecs) * 100.0));
        info.needReset = (lastResetCycle > 0 && cycleIndex > lastResetCycle);
    } else {
        std::tm tmStart = {};
        tmStart.tm_year = startY - 1900;
        tmStart.tm_mon = startM - 1;
        tmStart.tm_mday = startD;
        time_t tStart = std::mktime(&tmStart);

        double diffSec = (double)(nowTime - tStart);
        if (diffSec < 0) diffSec = 0;
        int cycleDays = (resetCycleDays > 0) ? resetCycleDays : 30;
        double cycleSec = cycleDays * 86400.0;
        int cycleIndex = (int)(diffSec / cycleSec) + 1;
        double currentCyclePassedSec = diffSec - (cycleIndex - 1) * cycleSec;

        info.curCycle = cycleIndex;
        info.cycleTotalDays = cycleDays;
        info.daysPassed = (int)(currentCyclePassedSec / 86400.0);
        info.daysRemaining = std::max(0, cycleDays - info.daysPassed);
        info.cyclePercent = std::min(100.0, std::max(0.0, (currentCyclePassedSec / cycleSec) * 100.0));

        time_t tCurStart = tStart + (time_t)((cycleIndex - 1) * cycleSec);
        time_t tNextReset = tStart + (time_t)(cycleIndex * cycleSec);
        std::tm tmBuf = {};
        char buf[32];
        localtime_r(&tCurStart, &tmBuf);
        std::strftime(buf, sizeof(buf), "%Y-%m-%d", &tmBuf);
        info.curCycleStart = buf;
        localtime_r(&tNextReset, &tmBuf);
        std::strftime(buf, sizeof(buf), "%Y-%m-%d", &tmBuf);
        info.nextResetDate = buf;
        info.needReset = (lastResetCycle > 0 && cycleIndex > lastResetCycle);
    }

    return info;
}

int ClashManager::RefreshSubscription(int subscriptionId) {
    ClashSubscription sub;
    if (!Database::Instance().GetSubscriptionById(subscriptionId, sub)) {
        std::cerr << "[ClashManager] Subscription not found: " << subscriptionId << std::endl;
        return -1;
    }

    SubscriptionUserInfo userInfo;
    std::string content = DownloadSubscription(sub.url, &userInfo);
    if (content.empty()) {
        std::cerr << "[ClashManager] Download failed for subscription: " << sub.name << std::endl;
        return -1;
    }

    auto rawNodes = ParseSubscriptionNodes(content);
    if (rawNodes.empty()) {
        std::cerr << "[ClashManager] No nodes parsed from: " << sub.name << std::endl;
        return -1;
    }

    auto newNodes = FilterAndDeduplicateNodes(rawNodes, sub.includeFilter, sub.excludeFilter);
    std::cout << "[ClashManager] Subscription '" << sub.name << "': filtered from " 
              << rawNodes.size() << " to " << newNodes.size() << " nodes" << std::endl;

    sub.rawContent = content;
    if (userInfo.uploadBytes > 0 || userInfo.downloadBytes > 0 || userInfo.totalBytes > 0) {
        sub.uploadBytes = userInfo.uploadBytes;
        sub.downloadBytes = userInfo.downloadBytes;
        sub.totalBytes = userInfo.totalBytes;
    }
    if (!userInfo.expireTime.empty()) sub.expireTime = userInfo.expireTime;
    if (!userInfo.websiteUrl.empty()) sub.websiteUrl = userInfo.websiteUrl;
    if (!userInfo.startDate.empty()) sub.resetStartDate = userInfo.startDate;
    else if (sub.resetStartDate.empty()) sub.resetStartDate = Utils::GetCurrentDate().substr(0, 10);

    sub.lastUpdated = Utils::GetCurrentDate();
    Database::Instance().SaveSubscription(sub);

    // 建立已有节点映射表（保留已有 ID、分组、监听端口等）
    auto existingSubPorts = Database::Instance().GetPortsBySubscriptionId(subscriptionId);
    std::map<std::string, std::string> nameToGroup;
    std::map<std::string, std::string> serverToGroup;
    for (const auto& p : existingSubPorts) {
        if (!p.groupName.empty()) {
            if (!p.clashNodeName.empty()) nameToGroup[p.clashNodeName] = p.groupName;
            if (!p.upstreamHost.empty()) {
                serverToGroup[p.upstreamHost + ":" + std::to_string(p.upstreamPort)] = p.groupName;
            }
        }
    }

    std::set<int> keepPortIds;
    std::set<size_t> matchedNewNodeIndices;
    int count = 0;

    for (auto& port : existingSubPorts) {
        int matchedIdx = -1;
        // 1. 同名优先匹配
        for (size_t i = 0; i < newNodes.size(); ++i) {
            if (matchedNewNodeIndices.count(i) > 0) continue;
            const auto& node = newNodes[i];
            if (!port.clashNodeName.empty() && node.name == port.clashNodeName) {
                matchedIdx = (int)i;
                break;
            }
        }
        // 2. 同服务器匹配 (若节点名称微调但服务器 host:port 相同)
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

            // 原地更新节点配置，关键：保留 port.id，这样分流规则绑定的单节点就不会丢失！
            port.upstreamType = "clash";
            port.upstreamHost = node.server;
            port.upstreamPort = node.port;
            port.clashNodeName = node.name;
            port.description = (sub.name.empty() ? "" : (sub.name + " - ")) + node.name;
            port.clashConfig = GenerateNodeConfig(node, 0);
            port.clashSubscriptionId = subscriptionId;
            if (port.groupName.empty()) {
                auto gIt = nameToGroup.find(node.name);
                if (gIt != nameToGroup.end()) {
                    port.groupName = gIt->second;
                }
            }
            Database::Instance().SaveProxyPort(port);
            count++;
        } else {
            // 该节点已从订阅中消失，删除该过期节点
            Database::Instance().DeleteProxyPort(port.id);
        }
    }

    // 将订阅中新增的节点添加为新端口
    for (size_t i = 0; i < newNodes.size(); ++i) {
        if (matchedNewNodeIndices.count(i) > 0) continue;
        const auto& node = newNodes[i];
        ProxyPort p;
        p.upstreamType = "clash";
        p.description = (sub.name.empty() ? "" : (sub.name + " - ")) + node.name;
        p.upstreamHost = node.server;
        p.upstreamPort = node.port;
        p.clashNodeName = node.name;

        auto gIt = nameToGroup.find(node.name);
        if (gIt != nameToGroup.end()) {
            p.groupName = gIt->second;
        } else {
            std::string sKey = node.server + ":" + std::to_string(node.port);
            auto sIt = serverToGroup.find(sKey);
            p.groupName = (sIt != serverToGroup.end()) ? sIt->second : "默认";
        }
        p.clashConfig = GenerateNodeConfig(node, 0);
        p.listenPort = 0;
        p.enabled = true;
        p.autoCheck = true;
        p.clashSubscriptionId = subscriptionId;
        if (Database::Instance().SaveProxyPort(p)) {
            count++;
        }
    }

    Database::Instance().DeduplicateProxyPorts();
    return count;
}
