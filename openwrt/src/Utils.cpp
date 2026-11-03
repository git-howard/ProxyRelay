#include "Utils.h"
#include <ctime>
#include <cstring>
#include <fstream>
#include <filesystem>
#include <regex>
#include <openssl/ssl.h>
#include <openssl/err.h>

namespace fs = std::filesystem;

namespace Utils {

static bool g_timezoneInitialized = false;

void InitTimezone() {
#ifndef _WIN32
    const char* envTz = getenv("TZ");
    if (!envTz || strlen(envTz) == 0) {
        std::ifstream tzFile("/etc/TZ");
        if (tzFile.is_open()) {
            std::string tz;
            std::getline(tzFile, tz);
            while (!tz.empty() && (tz.back() == '\r' || tz.back() == '\n' || tz.back() == ' ')) tz.pop_back();
            if (!tz.empty()) {
                setenv("TZ", tz.c_str(), 1);
            }
        } else {
            setenv("TZ", "CST-8", 1);
        }
    }
    tzset();
#endif
    g_timezoneInitialized = true;
}

std::string FormatTime(std::time_t time) {
    if (!g_timezoneInitialized) {
        InitTimezone();
    }
    char buf[64] = {};
    struct tm tm_buf;
    localtime_r(&time, &tm_buf);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    return buf;
}

std::string GetCurrentDateTime() {
    return FormatTime(std::time(nullptr));
}

std::string GetCurrentDate() {
    char buf[32] = {};
    std::time_t now = std::time(nullptr);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    strftime(buf, sizeof(buf), "%Y-%m-%d", &tm_buf);
    return buf;
}

std::string GetCurrentMonth() {
    char buf[16] = {};
    std::time_t now = std::time(nullptr);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    strftime(buf, sizeof(buf), "%Y-%m", &tm_buf);
    return buf;
}

std::string GetLastMonth() {
    std::time_t now = std::time(nullptr);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    tm_buf.tm_mon -= 1;
    std::mktime(&tm_buf);
    char buf[16] = {};
    strftime(buf, sizeof(buf), "%Y-%m", &tm_buf);
    return buf;
}

std::string GetCurrentWeek() {
    char buf[16] = {};
    std::time_t now = std::time(nullptr);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    strftime(buf, sizeof(buf), "%Y-%W", &tm_buf);
    return buf;
}

std::string GetCurrentWeekStartDate() {
    std::time_t now = std::time(nullptr);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    int wday = tm_buf.tm_wday;
    int daysToMonday = (wday == 0) ? 6 : (wday - 1);
    now -= daysToMonday * 86400;
    localtime_r(&now, &tm_buf);
    char buf[32] = {};
    strftime(buf, sizeof(buf), "%Y-%m-%d", &tm_buf);
    return buf;
}

std::string GetPastDate(int daysAgo) {
    std::time_t t = std::time(nullptr) - (daysAgo * 86400);
    struct tm tm_buf;
    localtime_r(&t, &tm_buf);
    char buf[32] = {};
    strftime(buf, sizeof(buf), "%Y-%m-%d", &tm_buf);
    return buf;
}

std::vector<std::string> GetPastDates(int count) {
    std::vector<std::string> dates;
    dates.reserve(count);
    for (int i = count - 1; i >= 0; --i) {
        dates.push_back(GetPastDate(i));
    }
    return dates;
}

int64_t GetCurrentTimestamp() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string FormatBytes(int64_t bytes) {
    constexpr double KB = 1024.0;
    constexpr double MB = KB * 1024.0;
    constexpr double GB = MB * 1024.0;
    constexpr double TB = GB * 1024.0;

    std::ostringstream ss;
    ss << std::fixed << std::setprecision(2);
    if (bytes >= TB) {
        ss << (bytes / TB) << " TB";
    } else if (bytes >= GB) {
        ss << (bytes / GB) << " GB";
    } else if (bytes >= MB) {
        ss << (bytes / MB) << " MB";
    } else if (bytes >= KB) {
        ss << (bytes / KB) << " KB";
    } else {
        ss << bytes << " B";
    }
    return ss.str();
}

static const std::string BASE64_CHARS =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string Base64Encode(const std::string& input) {
    std::string ret;
    int i = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    for (unsigned char c : input) {
        char_array_3[i++] = c;
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++) ret += BASE64_CHARS[char_array_4[i]];
            i = 0;
        }
    }

    if (i != 0) {
        for (int j = i; j < 3; j++) char_array_3[j] = '\0';
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (int j = 0; j < i + 1; j++) ret += BASE64_CHARS[char_array_4[j]];
        while (i++ < 3) ret += '=';
    }
    return ret;
}

std::string Base64Decode(const std::string& input) {
    auto is_base64 = [](unsigned char c) {
        return (isalnum(c) || (c == '+') || (c == '/'));
    };

    int in_len = input.size();
    int i = 0, in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::string ret;

    while (in_len-- && (input[in_] != '=') && is_base64(input[in_])) {
        char_array_4[i++] = input[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++) char_array_4[i] = BASE64_CHARS.find(char_array_4[i]);
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; i < 3; i++) ret += char_array_3[i];
            i = 0;
        }
    }

    if (i) {
        for (int j = 0; j < i; j++) char_array_4[j] = BASE64_CHARS.find(char_array_4[j]);
        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        for (int j = 0; j < i - 1; j++) ret += char_array_3[j];
    }
    return ret;
}

bool ParseBasicAuth(const std::string& authHeader, std::string& username, std::string& password) {
    if (authHeader.rfind("Basic ", 0) != 0) return false;
    std::string b64 = authHeader.substr(6);
    std::string decoded = Base64Decode(Trim(b64));
    size_t colon = decoded.find(':');
    if (colon == std::string::npos) return false;
    username = decoded.substr(0, colon);
    password = decoded.substr(colon + 1);
    return true;
}

std::string GetClientIP(const std::string& remoteAddr) {
    size_t colon = remoteAddr.rfind(':');
    if (colon != std::string::npos) {
        return remoteAddr.substr(0, colon);
    }
    return remoteAddr;
}

bool MatchCIDR(const std::string& ipStr, const std::string& cidrStr) {
    size_t slash = cidrStr.find('/');
    if (slash == std::string::npos) {
        return ipStr == cidrStr;
    }
    std::string netStr = cidrStr.substr(0, slash);
    int prefix = std::atoi(cidrStr.substr(slash + 1).c_str());
    if (prefix < 0 || prefix > 32) return false;

    struct in_addr ip, net;
    if (inet_pton(AF_INET, ipStr.c_str(), &ip) != 1) return false;
    if (inet_pton(AF_INET, netStr.c_str(), &net) != 1) return false;

    uint32_t mask = (prefix == 0) ? 0 : (~0U << (32 - prefix));
    uint32_t ipInt = ntohl(ip.s_addr);
    uint32_t netInt = ntohl(net.s_addr);
    return (ipInt & mask) == (netInt & mask);
}

bool IsIPAllowed(const std::string& clientIP, const std::string& allowedIPs) {
    if (allowedIPs.empty() || allowedIPs == "*") return true;
    auto ips = Split(allowedIPs, ',');
    for (auto& item : ips) {
        item = Trim(item);
        if (item.empty()) continue;
        if (item == "*" || MatchCIDR(clientIP, item)) {
            return true;
        }
    }
    return false;
}

bool IsPrivateIP(const std::string& ip) {
    if (ip.empty() || ip == "127.0.0.1" || ip == "localhost" || ip == "::1") return true;
    if (MatchCIDR(ip, "10.0.0.0/8") ||
        MatchCIDR(ip, "172.16.0.0/12") ||
        MatchCIDR(ip, "192.168.0.0/16") ||
        MatchCIDR(ip, "127.0.0.0/8") ||
        MatchCIDR(ip, "169.254.0.0/16")) {
        return true;
    }
    return false;
}

std::string Trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

std::vector<std::string> Split(const std::string& s, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

std::string ToLower(const std::string& s) {
    std::string res = s;
    std::transform(res.begin(), res.end(), res.begin(), ::tolower);
    return res;
}

void CleanOldLogs(int retentionDays) {
    try {
        if (!fs::exists("log")) return;
        auto now = std::chrono::system_clock::now();
        auto maxAge = std::chrono::hours(24 * retentionDays);
        for (const auto& entry : fs::directory_iterator("log")) {
            if (entry.is_regular_file()) {
                auto ftime = fs::last_write_time(entry);
                auto sTime = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                    ftime - fs::file_time_type::clock::now() + now);
                if (now - sTime > maxAge) {
                    fs::remove(entry);
                }
            }
        }
    } catch (...) {}
}

bool HttpGet(const std::string& url, std::string& responseBody, int timeoutSec) {
    // 支持直接使用 curl 工具或基础套接字拉取，适合 OpenWrt 环境
    std::string cmd = "curl -s -L --max-time " + std::to_string(timeoutSec) + " \"" + url + "\" 2>/dev/null";
    FILE* fp = popen(cmd.c_str(), "r");
    if (!fp) return false;

    char buffer[4096];
    std::string output;
    while (fgets(buffer, sizeof(buffer), fp) != nullptr) {
        output.append(buffer);
    }
    pclose(fp);
    if (!output.empty()) {
        responseBody = std::move(output);
        return true;
    }
    return false;
}

std::string ExecCmd(const std::string& cmd) {
    FILE* fp = popen(cmd.c_str(), "r");
    if (!fp) return "";
    char buffer[2048];
    std::string output;
    while (fgets(buffer, sizeof(buffer), fp) != nullptr) {
        output.append(buffer);
    }
    pclose(fp);
    return output;
}

} // namespace Utils
