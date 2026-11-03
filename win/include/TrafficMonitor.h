#pragma once

#include <atomic>
#include <mutex>
#include <vector>
#include <deque>
#include <thread>
#include <chrono>
#include <functional>
#include <map>
#include <memory>

struct RealtimeTrafficData {
    int64_t timestamp;
    int64_t uploadSpeed;
    int64_t downloadSpeed;
    int64_t totalUpload;
    int64_t totalDownload;
};

struct UserTrafficData {
    int userId;
    std::atomic<int64_t> sessionUpload{0};
    std::atomic<int64_t> sessionDownload{0};
    std::atomic<int64_t> lastUploadSpeed{0};
    std::atomic<int64_t> lastDownloadSpeed{0};
};

class TrafficMonitor {
public:
    static TrafficMonitor& Instance();
    
    void Start();
    void Stop();
    
    void RecordUpload(int userId, int portId, int64_t bytes);
    void RecordDownload(int userId, int portId, int64_t bytes);
    
    RealtimeTrafficData GetCurrentData() const;
    std::vector<RealtimeTrafficData> GetRecentHistory(int seconds = 60) const;
    
    // 获取统计信息的结构体
    struct Stats {
        int64_t uploadSpeed = 0;
        int64_t downloadSpeed = 0;
        int64_t upload1h = 0;     // 最近1小时上传
        int64_t download1h = 0;   // 最近1小时下载
        int64_t upload24h = 0;    // 最近24小时上传
        int64_t download24h = 0;  // 最近24小时下载
        int64_t uploadWeek = 0;   // 本周上传
        int64_t downloadWeek = 0; // 本周下载
        int64_t uploadMonth = 0;  // 本月上传
        int64_t downloadMonth = 0;// 本月下载
        int64_t uploadLastMonth = 0;   // 上月上传
        int64_t downloadLastMonth = 0; // 上月下载
    };
    
    Stats GetUserStats(int userId) const;
    Stats GetPortStats(int portId) const;
    void GetUserUnpersistedTraffic(int userId, int64_t& upload, int64_t& download) const;
    void GetPortUnpersistedTraffic(int portId, int64_t& upload, int64_t& download) const;
    void GetAllUnpersistedTraffic(int64_t& upload, int64_t& download) const;
    void GetAllPortUnpersistedTraffic(int64_t& upload, int64_t& download) const;
    
    
    int64_t GetCurrentUploadSpeed() const { return currentUploadSpeed_.load(); }
    int64_t GetCurrentDownloadSpeed() const { return currentDownloadSpeed_.load(); }
    int64_t GetTotalUpload() const { return totalUpload_.load(); }
    int64_t GetTotalDownload() const { return totalDownload_.load(); }
    
    using TrafficCallback = std::function<void(const RealtimeTrafficData&)>;
    void SetCallback(TrafficCallback callback) { callback_ = callback; }
    void PersistTraffic();
    
private:
    TrafficMonitor() = default;
    ~TrafficMonitor();
    
    void MonitorThread();
    
    // 内部流量数据结构
    struct TrafficEntity {
        int id;
        std::atomic<int64_t> sessionUpload{0};
        std::atomic<int64_t> sessionDownload{0};
        int64_t lastSecondUpload = 0;
        int64_t lastSecondDownload = 0;
        int64_t currentUploadSpeed = 0;
        int64_t currentDownloadSpeed = 0;
        
        // 历史数据 (每分钟一个点，存储最近1440分钟即24小时的数据)
        struct MinuteData {
            int64_t upload = 0;
            int64_t download = 0;
        };
        std::deque<MinuteData> historyBytes; 
        
        // 当前这一分钟的累积
        int64_t currentMinuteUpload = 0;
        int64_t currentMinuteDownload = 0;
        
        // 本周/本月累积流量（持久化存储）
        int64_t weekUpload = 0;
        int64_t weekDownload = 0;
        int64_t monthUpload = 0;
        int64_t monthDownload = 0;
        int64_t lastMonthUpload = 0;   // 上月上传
        int64_t lastMonthDownload = 0; // 上月下载
        std::string lastWeekKey;   // 用于检测周变更 (格式: YYYY-WW)
        std::string lastMonthKey;  // 用于检测月变更 (格式: YYYY-MM)
        
        void UpdateSpeed();
        void TickMinute();
        Stats CalculateStats() const;
    };
    
    TrafficEntity* GetOrCreateUserEntity(int userId);
    TrafficEntity* GetOrCreatePortEntity(int portId);
    
    // 保存和加载流量统计
    void SaveTrafficStats();
    void LoadTrafficStats();
    
    std::atomic<bool> running_{false};
    std::thread monitorThread_;
    
    std::atomic<int64_t> totalUpload_{0};
    std::atomic<int64_t> totalDownload_{0};
    std::atomic<int64_t> currentUploadSpeed_{0};
    std::atomic<int64_t> currentDownloadSpeed_{0};
    std::atomic<int64_t> lastSecondUpload_{0};
    std::atomic<int64_t> lastSecondDownload_{0};
    
    mutable std::mutex historyMutex_;
    std::deque<RealtimeTrafficData> history_;
    static const size_t MAX_HISTORY_SIZE = 300;
    
    mutable std::mutex statsMutex_;
    std::map<int, std::unique_ptr<TrafficEntity>> userStats_;
    std::map<int, std::unique_ptr<TrafficEntity>> portStats_;
    
    TrafficCallback callback_;
    int persistCounter_ = 0;
    int minuteCounter_ = 0;
};
