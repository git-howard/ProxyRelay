#pragma once

#include "Common.h"
#include <string>
#include <vector>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace Utils {

// 时间与日期格式化
void InitTimezone();
std::string FormatTime(std::time_t time);
std::string GetCurrentDateTime();
std::string GetCurrentDate();
std::string GetCurrentMonth();
std::string GetLastMonth();
std::string GetCurrentWeek();
std::string GetCurrentWeekStartDate();
std::string GetPastDate(int daysAgo);
std::vector<std::string> GetPastDates(int count);
int64_t GetCurrentTimestamp();

// 流量格式化 (B -> KB, MB, GB)
std::string FormatBytes(int64_t bytes);

// Base64 编解码
std::string Base64Encode(const std::string& input);
std::string Base64Decode(const std::string& input);

// HTTP 认证头解析 (Basic auth)
bool ParseBasicAuth(const std::string& authHeader, std::string& username, std::string& password);

// IP 地址处理与 CIDR 匹配
std::string GetClientIP(const std::string& remoteAddr);
bool IsIPAllowed(const std::string& clientIP, const std::string& allowedIPs);
bool MatchCIDR(const std::string& ip, const std::string& cidr);
bool IsPrivateIP(const std::string& ip);

// 轻量 HTTP/HTTPS GET 客户端 (用于拉取订阅)
bool HttpGet(const std::string& url, std::string& responseBody, int timeoutSec = 10);

// 日志清理
void CleanOldLogs(int retentionDays);

// 字符串工具
std::string Trim(const std::string& s);
std::vector<std::string> Split(const std::string& s, char delimiter);
std::string ToLower(const std::string& s);

// 命令行执行
std::string ExecCmd(const std::string& cmd);

} // namespace Utils
