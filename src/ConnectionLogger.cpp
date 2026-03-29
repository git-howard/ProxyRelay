#include "ConnectionLogger.h"
#include "Database.h"
#include "Utils.h"
#include <filesystem>
#include <sstream>
#include <iomanip>
#include <chrono>

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
                           const std::string& action, const std::string& proxyDesc) {
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
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // 添加到内存队列
        recentLogs_.push_back(entry);
        while (recentLogs_.size() > MAX_RECENT_LOGS) {
            recentLogs_.pop_front();
        }
        
        // 写入文件
        WriteToFile(entry);
        
        // 回调UI
        if (uiCallback_) {
            uiCallback_(entry);
        }
    }
}

std::vector<ConnectionLogEntry> ConnectionLogger::GetRecentLogs(size_t count) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ConnectionLogEntry> result;
    
    size_t start = 0;
    if (recentLogs_.size() > count) {
        start = recentLogs_.size() - count;
    }
    
    for (size_t i = start; i < recentLogs_.size(); ++i) {
        result.push_back(recentLogs_[i]);
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
        logFile_ << entry.timestamp << " | " 
                 << entry.action << " | "
                 << entry.proxyDesc << " | "
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

