#pragma once

#include "pch.h"
#include <string>
#include <vector>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <windows.h>
#include <commctrl.h>

namespace Utils {

// Tooltips
HWND CreateToolTip(HWND hwndOwner);
void SetToolTip(HWND hwndTT, HWND hwndTool, const std::wstring& text);

// 字符串转换
std::wstring StringToWString(const std::string& str);
std::string WStringToString(const std::wstring& wstr);

// 时间格式化
std::string FormatTime(std::time_t time);
std::string GetCurrentDate();
std::string GetCurrentMonth();
std::string GetLastMonth();    // 上月月份 (格式: YYYY-MM)
std::string GetCurrentWeek();  // 格式: YYYY-WW
int64_t GetCurrentTimestamp();

// 流量格式化
std::string FormatBytes(int64_t bytes);
std::wstring FormatBytesW(int64_t bytes);

// Base64编解码
std::string Base64Encode(const std::string& input);
std::string Base64Decode(const std::string& input);

// 解析HTTP认证头
bool ParseBasicAuth(const std::string& authHeader, std::string& username, std::string& password);

// IP地址处理
std::string GetClientIP(const std::string& remoteAddr);
bool IsIPAllowed(const std::string& clientIP, const std::string& allowedIPs);

// 解析代理URL
struct ProxyInfo {
    std::string type;  // "http" or "socks5"
    std::string host;
    int port;
    std::string username;
    std::string password;
};
bool ParseProxyURL(const std::string& url, ProxyInfo& info);

// 日志
void Log(const std::string& message);
void LogError(const std::string& message);
void LogAuth(const std::string& message);  // 登录日志（内部使用）
void LogAuthSuccess(const std::string& user, const std::string& ip, const std::string& protocol);  // 成功认证（去重）
void LogAuthFailed(const std::string& user, const std::string& ip, const std::string& protocol);   // 失败认证
void CleanOldLogs(int retentionDays);
void CopyToClipboard(const std::wstring& text);

} // namespace Utils
