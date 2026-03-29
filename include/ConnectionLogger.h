#pragma once

#include <string>
#include <vector>
#include <mutex>
#include <fstream>
#include <functional>
#include <deque>

struct ConnectionLogEntry {
    std::string timestamp;
    std::string username;
    std::string clientIP;
    std::string targetHost;
    int targetPort;
    std::string action;  // "CONNECT", "REQUEST", etc.
    std::string proxyDesc; // 代理备注
};

class ConnectionLogger {
public:
    static ConnectionLogger& Instance();
    
    void Log(const std::string& username, const std::string& clientIP, 
             const std::string& targetHost, int targetPort, const std::string& action,
             const std::string& proxyDesc);
    
    // 获取最近的日志条目
    std::vector<ConnectionLogEntry> GetRecentLogs(size_t count = 100);
    
    // 设置UI回调
    void SetUICallback(std::function<void(const ConnectionLogEntry&)> callback);
    
private:
    ConnectionLogger();
    ~ConnectionLogger() = default;
    
    void EnsureLogFile();
    void WriteToFile(const ConnectionLogEntry& entry);
    void CleanupOldLogs();  // 清理超过保留期的日志文件
    
    std::mutex mutex_;
    std::deque<ConnectionLogEntry> recentLogs_;
    static const size_t MAX_RECENT_LOGS = 500;
    static const int LOG_RETENTION_DAYS = 30;  // 日志保留天数
    
    std::ofstream logFile_;
    std::string currentLogDate_;
    std::function<void(const ConnectionLogEntry&)> uiCallback_;
};
