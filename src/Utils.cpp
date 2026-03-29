#include "Utils.h"
#include <fstream>
#include <mutex>
#include <regex>
#include <filesystem>
#include <set>

namespace Utils {

HWND CreateToolTip(HWND hwndOwner) {
    if (!hwndOwner) return nullptr;
    
    // Create the tooltip.
    HWND hwndTT = CreateWindowExW(0, TOOLTIPS_CLASSW, NULL,
        WS_POPUP | TTS_ALWAYSTIP | TTS_NOPREFIX,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        hwndOwner, NULL, GetModuleHandle(NULL), NULL);
        
    if (hwndTT) {
        SetWindowPos(hwndTT, HWND_TOPMOST, 0, 0, 0, 0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
            
        // Set maximum width so tooltips can wrap
        SendMessage(hwndTT, TTM_SETMAXTIPWIDTH, 0, 400); 
    }
    return hwndTT;
}

void SetToolTip(HWND hwndTT, HWND hwndTool, const std::wstring& text) {
    if (!hwndTT || !hwndTool || text.empty()) return;

    TOOLINFOW ti = { 0 };
    ti.cbSize = sizeof(TOOLINFOW);
    ti.uFlags = TTF_SUBCLASS | TTF_IDISHWND;
    ti.hwnd = GetParent(hwndTool);
    ti.uId = (UINT_PTR)hwndTool;
    ti.hinst = GetModuleHandle(NULL);
    ti.lpszText = (LPWSTR)text.c_str();

    SendMessage(hwndTT, TTM_ADDTOOLW, 0, (LPARAM)&ti);
}

static std::mutex logMutex;
static std::set<std::string> authSuccessRecorded;  // 记录已登录成功的 user+ip 组合
static std::string authSuccessDate;  // 当前日期，用于每天重置

// IPv4 CIDR 转换助手
static bool ParseCIDR(const std::string& cidrStr, unsigned int& ip, unsigned int& mask) {
    size_t slash = cidrStr.find('/');
    std::string ipStr = cidrStr;
    int prefix = 32;
    
    if (slash != std::string::npos) {
        ipStr = cidrStr.substr(0, slash);
        prefix = std::atoi(cidrStr.substr(slash + 1).c_str());
    }
    
    if (inet_pton(AF_INET, ipStr.c_str(), &ip) == 1) {
        if (prefix < 0) prefix = 0;
        if (prefix > 32) prefix = 32;
        
        if (prefix == 0) mask = 0;
        else {
            unsigned int m = 0xFFFFFFFF << (32 - prefix);
            mask = htonl(m);
        }
        ip = ip & mask;
        return true;
    }
    return false;
}

static bool MatchCIDR(unsigned int clientIP, const std::string& cidrStr) {
    unsigned int ip, mask;
    if (ParseCIDR(cidrStr, ip, mask)) {
        return (clientIP & mask) == ip;
    }
    return false;
}

std::wstring StringToWString(const std::string& str) {
    if (str.empty()) return L"";
    int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    std::wstring result(size - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &result[0], size);
    return result;
}

std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string result(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], size, nullptr, nullptr);
    return result;
}

std::string FormatTime(std::time_t time) {
    std::tm tm;
    localtime_s(&tm, &time);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

std::string GetCurrentDate() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm;
    localtime_s(&tm, &time);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d");
    return oss.str();
}

std::string GetCurrentMonth() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm;
    localtime_s(&tm, &time);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m");
    return oss.str();
}

std::string GetLastMonth() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm;
    localtime_s(&tm, &time);
    
    // 计算上月
    if (tm.tm_mon == 0) {
        // 当前是1月，上月是上年12月
        tm.tm_year -= 1;
        tm.tm_mon = 11;  // 12月 (0-indexed)
    } else {
        tm.tm_mon -= 1;
    }
    
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m");
    return oss.str();
}

std::string GetCurrentWeek() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm;
    localtime_s(&tm, &time);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%W");  // %W = ISO week number (00-53)
    return oss.str();
}

int64_t GetCurrentTimestamp() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

std::string FormatBytes(int64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unitIndex = 0;
    double size = static_cast<double>(bytes);
    
    while (size >= 1024 && unitIndex < 4) {
        size /= 1024;
        unitIndex++;
    }
    
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << size << " " << units[unitIndex];
    return oss.str();
}

std::wstring FormatBytesW(int64_t bytes) {
    return StringToWString(FormatBytes(bytes));
}

static const std::string base64_chars = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

std::string Base64Encode(const std::string& input) {
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    size_t in_len = input.size();
    const char* bytes_to_encode = input.c_str();

    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for(i = 0; i < 4; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for(j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (j = 0; j < i + 1; j++)
            ret += base64_chars[char_array_4[j]];

        while((i++ < 3))
            ret += '=';
    }

    return ret;
}

std::string Base64Decode(const std::string& encoded_string) {
    size_t in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::string ret;

    while (in_len-- && encoded_string[in_] != '=' && 
           (isalnum(encoded_string[in_]) || encoded_string[in_] == '+' || encoded_string[in_] == '/')) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = static_cast<unsigned char>(base64_chars.find(char_array_4[i]));

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; i < 3; i++)
                ret += char_array_3[i];
            i = 0;
        }
    }

    if (i) {
        for (j = 0; j < i; j++)
            char_array_4[j] = static_cast<unsigned char>(base64_chars.find(char_array_4[j]));

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);

        for (j = 0; j < i - 1; j++) 
            ret += char_array_3[j];
    }

    return ret;
}

bool ParseBasicAuth(const std::string& authHeader, std::string& username, std::string& password) {
    // Format: "Basic base64(username:password)"
    if (authHeader.substr(0, 6) != "Basic ") {
        return false;
    }
    
    std::string encoded = authHeader.substr(6);
    std::string decoded = Base64Decode(encoded);
    
    size_t colonPos = decoded.find(':');
    if (colonPos == std::string::npos) {
        return false;
    }
    
    username = decoded.substr(0, colonPos);
    password = decoded.substr(colonPos + 1);
    return true;
}

std::string GetClientIP(const std::string& remoteAddr) {
    // 去除端口号
    size_t colonPos = remoteAddr.rfind(':');
    if (colonPos != std::string::npos) {
        return remoteAddr.substr(0, colonPos);
    }
    return remoteAddr;
}

bool IsIPAllowed(const std::string& clientIP, const std::string& allowedIPs) {
    if (allowedIPs.empty() || allowedIPs == "*") {
        return true;
    }
    
    unsigned int clientIPVal = 0;
    bool hasClientIPVal = (inet_pton(AF_INET, clientIP.c_str(), &clientIPVal) == 1);
    
    // 支持逗号分隔的多个IP
    std::istringstream iss(allowedIPs);
    std::string ip;
    while (std::getline(iss, ip, ',')) {
        // 去除空格
        ip.erase(std::remove_if(ip.begin(), ip.end(), ::isspace), ip.end());
        if (ip.empty()) continue;

        if (ip == clientIP) {
            return true;
        }
        
        // 支持 CIDR /24
        if (hasClientIPVal && ip.find('/') != std::string::npos) {
            if (MatchCIDR(clientIPVal, ip)) return true;
        }

        // 支持简单的通配符匹配 (192.168.1.*)
        if (ip.back() == '*') {
            std::string prefix = ip.substr(0, ip.length() - 1);
            if (clientIP.substr(0, prefix.length()) == prefix) {
                return true;
            }
        }
    }
    return false;
}

bool ParseProxyURL(const std::string& url, ProxyInfo& info) {
    // 格式: type://[username:password@]host:port
    std::regex pattern(R"(^(https?|socks5)://(?:([^:]+):([^@]+)@)?([^:]+):(\d+)$)");
    std::smatch match;
    
    if (std::regex_match(url, match, pattern)) {
        info.type = match[1].str();
        if (info.type == "https") info.type = "http";
        info.username = match[2].str();
        info.password = match[3].str();
        info.host = match[4].str();
        info.port = std::stoi(match[5].str());
        return true;
    }
    return false;
}

void Log(const std::string& message) {
    std::lock_guard<std::mutex> lock(logMutex);
    
    // 确保 log 目录存在
    std::filesystem::create_directories("log");
    
    // 按天分割日志文件
    std::string date = GetCurrentDate();
    std::string logPath = "log/proxy_" + date + ".log";
    
    std::ofstream logFile(logPath, std::ios::app);
    if (logFile.is_open()) {
        logFile << "[" << FormatTime(std::time(nullptr)) << "] " << message << std::endl;
    }
}

void LogError(const std::string& message) {
    Log("[ERROR] " + message);
}

void LogAuth(const std::string& message) {
    std::lock_guard<std::mutex> lock(logMutex);
    
    // 确保 log 目录存在
    std::filesystem::create_directories("log");
    
    // 按天分割登录日志文件
    std::string date = GetCurrentDate();
    std::string logPath = "log/auth_" + date + ".log";
    
    std::ofstream logFile(logPath, std::ios::app);
    if (logFile.is_open()) {
        logFile << "[" << FormatTime(std::time(nullptr)) << "] " << message << std::endl;
    }
}

void LogAuthSuccess(const std::string& user, const std::string& ip, const std::string& protocol) {
    std::lock_guard<std::mutex> lock(logMutex);
    
    std::string currentDate = GetCurrentDate();
    
    // 每天重置去重记录
    if (authSuccessDate != currentDate) {
        authSuccessRecorded.clear();
        authSuccessDate = currentDate;
    }
    
    // 检查是否已记录过该 user+ip 组合
    std::string key = user + "@" + ip;
    if (authSuccessRecorded.find(key) != authSuccessRecorded.end()) {
        // 已记录，不重复写入
        return;
    }
    
    // 标记为已记录
    authSuccessRecorded.insert(key);
    
    // 写入日志
    std::filesystem::create_directories("log");
    std::string logPath = "log/auth_" + currentDate + ".log";
    
    std::ofstream logFile(logPath, std::ios::app);
    if (logFile.is_open()) {
        logFile << "[" << FormatTime(std::time(nullptr)) << "] " 
                << protocol << " Auth SUCCESS: user=" << user << ", ip=" << ip << std::endl;
    }
}

void LogAuthFailed(const std::string& user, const std::string& ip, const std::string& protocol) {
    std::lock_guard<std::mutex> lock(logMutex);
    
    std::filesystem::create_directories("log");
    std::string date = GetCurrentDate();
    std::string logPath = "log/auth_" + date + ".log";
    
    std::ofstream logFile(logPath, std::ios::app);
    if (logFile.is_open()) {
        logFile << "[" << FormatTime(std::time(nullptr)) << "] " 
                << protocol << " Auth FAILED: user=" << user << ", ip=" << ip << std::endl;
    }
}

void CleanOldLogs(int retentionDays) {
    std::lock_guard<std::mutex> lock(logMutex);
    
    if (retentionDays <= 0) retentionDays = 30;  // 默认30天
    
    try {
        if (!std::filesystem::exists("log")) return;
        
        auto now = std::chrono::system_clock::now();
        auto cutoff = now - std::chrono::hours(24 * retentionDays);
        
        for (const auto& entry : std::filesystem::directory_iterator("log")) {
            if (entry.is_regular_file() && entry.path().extension() == ".log") {
                auto fileTime = std::filesystem::last_write_time(entry.path());
                // 转换文件时间到 system_clock
                auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                    fileTime - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
                
                if (sctp < cutoff) {
                    std::filesystem::remove(entry.path());
                }
            }
        }
    } catch (...) {
        // 忽略清理错误
    }
}

void CopyToClipboard(const std::wstring& text) {
    if (!OpenClipboard(nullptr)) return;
    EmptyClipboard();
    size_t size = (text.length() + 1) * sizeof(wchar_t);
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, size);
    if (hMem) {
        void* ptr = GlobalLock(hMem);
        if (ptr) {
            memcpy(ptr, text.c_str(), size);
            GlobalUnlock(hMem);
            SetClipboardData(CF_UNICODETEXT, hMem);
        }
    }
    CloseClipboard();
}

} // namespace Utils
