#include "ConnectionLogger.h"
#include "Database.h"
#include "SharedStatusManager.h"
#include "Utils.h"
#include <filesystem>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <unordered_set>
#include <algorithm>

ConnectionLogger& ConnectionLogger::Instance() {
    static ConnectionLogger instance;
    return instance;
}

ConnectionLogger::ConnectionLogger() {
    // 确保日志目录存在
    std::filesystem::create_directories("log");
    
    // 清理超期的日志文件
    CleanupOldLogs();
}

void ConnectionLogger::Log(const std::string& username, const std::string& clientIP,
                           const std::string& targetHost, int targetPort, 
                           const std::string& action, const std::string& proxyDesc,
                           const std::string& inboundType) {
    ConnectionLogEntry entry;
    
    // 获取当前时间
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm;
    localtime_s(&tm, &time);
    
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    entry.timestamp = oss.str();
    entry.username = username;
    entry.clientIP = clientIP;
    entry.targetHost = targetHost;
    entry.targetPort = targetPort;
    entry.action = action;
    entry.proxyDesc = proxyDesc;
    if (action.find("UDP") != std::string::npos || inboundType.find("UDP") != std::string::npos) {
        entry.protocol = "UDP";
    } else {
        entry.protocol = "TCP";
    }
    if (!inboundType.empty()) {
        entry.inboundType = inboundType;
    } else if (action.find("SOCKS5") != std::string::npos) {
        entry.inboundType = "SOCKS5";
    } else if (action == "CONNECT" || targetPort == 443) {
        entry.inboundType = "HTTPS";
    } else {
        entry.inboundType = "HTTP";
    }
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // 添加到内存队列
        recentLogs_.push_back(entry);
        while (recentLogs_.size() > MAX_RECENT_LOGS) {
            recentLogs_.pop_front();
        }
        
        // 写入文件
        WriteToFile(entry);

        // 写入跨进程共享内存（供桌面控制台获取实时审计日志）
        SharedStatusManager::Instance().AddLogEntry(entry);
    }
    
    // UI 回调移到锁外执行，避免持锁时间过长导致锁竞争
    if (uiCallback_) {
        uiCallback_(entry);
    }
}

static bool ParseLogLine(const std::string& line, ConnectionLogEntry& entry) {
    if (line.empty() || line[0] == '[') return false;
    std::vector<std::string> parts;
    size_t start = 0;
    while (true) {
        size_t pos = line.find(" | ", start);
        if (pos == std::string::npos) {
            parts.push_back(line.substr(start));
            break;
        }
        parts.push_back(line.substr(start, pos - start));
        start = pos + 3;
    }
    if (parts.size() < 6) return false;
    entry.timestamp = parts[0];
    entry.action = parts[1];

    // 日志写入格式: timestamp | action | proxyDesc | username | clientIP | targetHost:targetPort
    // 代理节点备注 (proxyDesc) 经常包含 " | "（例如节点备注 "ikuuu - 🇯🇵 日本W02 | IEPL" 或 "节点 | 下载专用 | x0.01"）
    // 因此末尾3列固定为: 倒数第3列=username, 倒数第2列=clientIP, 倒数第1列=targetHost:targetPort
    // 中间的 parts[2] 到 parts[n-4] 为 proxyDesc 本身被 " | " 切割后的所有片段，需重新拼合
    size_t n = parts.size();
    entry.username = parts[n - 3];
    entry.clientIP = parts[n - 2];

    std::string desc = parts[2];
    for (size_t i = 3; i <= n - 4; ++i) {
        desc += " | " + parts[i];
    }
    entry.proxyDesc = desc;
    
    const std::string& target = parts[n - 1];
    size_t colon = target.rfind(':');
    if (colon != std::string::npos) {
        entry.targetHost = target.substr(0, colon);
        try {
            entry.targetPort = std::stoi(target.substr(colon + 1));
        } catch (...) {
            entry.targetPort = 0;
        }
    } else {
        entry.targetHost = target;
        entry.targetPort = 0;
    }

    if (entry.action.find("SOCKS5") != std::string::npos) {
        entry.inboundType = "SOCKS5";
    } else if (entry.action == "CONNECT" || entry.targetPort == 443) {
        entry.inboundType = "HTTPS";
    } else {
        entry.inboundType = "HTTP";
    }

    return true;
}

void ConnectionLogger::ReadLogsFromFile(size_t count, std::vector<ConnectionLogEntry>& logs) {
    namespace fs = std::filesystem;
    try {
        if (!fs::exists("log")) return;

        // 记录已有条目用于去重
        std::unordered_set<std::string> existingKeys;
        for (const auto& e : logs) {
            existingKeys.insert(e.timestamp + "|" + e.clientIP + "|" + e.targetHost + ":" + std::to_string(e.targetPort));
        }

        // 收集 log/proxy_*.log 文件名列表，降序排序（优先读最新日期）
        std::vector<fs::path> logFiles;
        for (const auto& dirEntry : fs::directory_iterator("log")) {
            if (!dirEntry.is_regular_file()) continue;
            std::string name = dirEntry.path().filename().string();
            if (name.rfind("proxy_", 0) == 0 && name.rfind(".log") == name.length() - 4) {
                logFiles.push_back(dirEntry.path());
            }
        }
        std::sort(logFiles.rbegin(), logFiles.rend());

        std::vector<ConnectionLogEntry> fetched;
        for (const auto& filePath : logFiles) {
            if (logs.size() + fetched.size() >= count) break;

            std::ifstream fin(filePath);
            if (!fin.is_open()) continue;

            std::vector<std::string> lines;
            std::string line;
            while (std::getline(fin, line)) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (!line.empty()) lines.push_back(line);
            }
            fin.close();

            // 从文件末尾向前读取最新日志
            for (auto it = lines.rbegin(); it != lines.rend(); ++it) {
                if (logs.size() + fetched.size() >= count) break;
                ConnectionLogEntry e;
                if (ParseLogLine(*it, e)) {
                    std::string key = e.timestamp + "|" + e.clientIP + "|" + e.targetHost + ":" + std::to_string(e.targetPort);
                    if (existingKeys.insert(key).second) {
                        fetched.push_back(std::move(e));
                    }
                }
            }
        }

        // fetched 是从新到旧收集的，反转回时间正序（从旧到新），拼接到 logs 前面
        std::reverse(fetched.begin(), fetched.end());
        fetched.insert(fetched.end(), logs.begin(), logs.end());
        logs = std::move(fetched);

        // 按时间戳严格倒序排序，确保最新产生的日志排在最前面 (最上面)
        std::stable_sort(logs.begin(), logs.end(), [](const ConnectionLogEntry& a, const ConnectionLogEntry& b) {
            return a.timestamp > b.timestamp;
        });
    } catch (...) {
        // 文件读取容错
    }
}

std::vector<ConnectionLogEntry> ConnectionLogger::GetRecentLogs(size_t count) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ConnectionLogEntry> result;
    
    // 如果本地内存队列中有日志（例如核心服务进程自身，或者非服务模式），先从本地取（从后向前取最新日志）
    if (!recentLogs_.empty()) {
        for (auto it = recentLogs_.rbegin(); it != recentLogs_.rend() && result.size() < count; ++it) {
            result.push_back(*it);
        }
        return result;
    }

    // 控制台模式下（本地内存为空），优先尝试从跨进程共享内存读取实时日志
    std::vector<ConnectionLogEntry> sharedLogs;
    if (SharedStatusManager::Instance().ReadRecentLogs(count, sharedLogs) && !sharedLogs.empty()) {
        result = std::move(sharedLogs);
    }

    // 如果日志条数少于需求或共享内存为空，从磁盘日志文件逆向解析补齐历史日志
    if (result.size() < count) {
        ReadLogsFromFile(count, result);
    }

    return result;
}

void ConnectionLogger::SetUICallback(std::function<void(const ConnectionLogEntry&)> callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    uiCallback_ = callback;
}

void ConnectionLogger::EnsureLogFile() {
    std::string today = Utils::GetCurrentDate();
    
    if (today != currentLogDate_) {
        if (logFile_.is_open()) {
            logFile_.close();
        }
        
        std::string filename = "log/proxy_" + today + ".log";
        logFile_.open(filename, std::ios::app);
        currentLogDate_ = today;
    }
}

void ConnectionLogger::WriteToFile(const ConnectionLogEntry& entry) {
    EnsureLogFile();
    
    if (logFile_.is_open()) {
        std::string cleanDesc = entry.proxyDesc;
        for (char& c : cleanDesc) {
            if (c == '\r' || c == '\n') c = ' ';
        }
        logFile_ << entry.timestamp << " | " 
                 << entry.action << " | "
                 << cleanDesc << " | "
                 << entry.username << " | " 
                 << entry.clientIP << " | "
                 << entry.targetHost << ":" << entry.targetPort
                 << std::endl;
        logFile_.flush();
    }
}

void ConnectionLogger::CleanupOldLogs() {
    namespace fs = std::filesystem;
    
    try {
        // 从数据库读取保留天数，默认30天
        int retentionDays = LOG_RETENTION_DAYS;
        std::string configDays = Database::Instance().GetConfig("log_retention_days", "30");
        int configVal = std::atoi(configDays.c_str());
        if (configVal > 0) {
            retentionDays = configVal;
        }
        
        auto now = std::chrono::system_clock::now();
        
        for (const auto& entry : fs::directory_iterator("log")) {
            if (!entry.is_regular_file()) continue;
            
            std::string filename = entry.path().filename().string();
            // 检查是否是代理日志文件 (proxy_YYYY-MM-DD.log)
            if (filename.length() < 21 || filename.substr(0, 6) != "proxy_" || 
                filename.substr(filename.length() - 4) != ".log") {
                continue;
            }
            
            // 提取日期部分
            std::string dateStr = filename.substr(6, 10);  // YYYY-MM-DD
            
            // 解析日期
            std::tm tm = {};
            std::istringstream ss(dateStr);
            ss >> std::get_time(&tm, "%Y-%m-%d");
            if (ss.fail()) continue;
            
            auto fileDate = std::chrono::system_clock::from_time_t(std::mktime(&tm));
            auto age = std::chrono::duration_cast<std::chrono::hours>(now - fileDate).count() / 24;
            
            if (age > retentionDays) {
                fs::remove(entry.path());
            }
        }
    } catch (...) {
        // 清理失败不影响程序运行
    }
}

void ConnectionLogger::GetStorageInfo(int64_t& totalBytes, int& fileCount) {
    namespace fs = std::filesystem;
    totalBytes = 0;
    fileCount = 0;
    try {
        if (fs::exists("log")) {
            for (const auto& entry : fs::directory_iterator("log")) {
                if (entry.is_regular_file()) {
                    std::string fn = entry.path().filename().string();
                    if (fn.rfind("proxy_", 0) == 0 && fn.size() >= 4 && fn.substr(fn.size() - 4) == ".log") {
                        totalBytes += (int64_t)entry.file_size();
                        fileCount++;
                    }
                }
            }
        }
    } catch (...) {}
}

