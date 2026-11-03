#pragma once

#include "Common.h"
#include <atomic>
#include <mutex>
#include <vector>
#include <deque>
#include <thread>
#include <map>

struct RealtimeTrafficData {
    int64_t timestamp;
    int64_t uploadSpeed;
    int64_t downloadSpeed;
    int64_t totalUpload;
    int64_t totalDownload;
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

    int64_t GetTotalUpload() const { return totalUpload_.load(); }
    int64_t GetTotalDownload() const { return totalDownload_.load(); }

    void PersistTraffic();
    void GetUserUnpersistedTraffic(int userId, int64_t& upload, int64_t& download) const;

private:
    TrafficMonitor();
    ~TrafficMonitor();

    void MonitorLoop();

    std::atomic<bool> running_{false};
    std::thread workerThread_;

    std::atomic<int64_t> totalUpload_{0};
    std::atomic<int64_t> totalDownload_{0};

    std::atomic<int64_t> currentUploadSpeed_{0};
    std::atomic<int64_t> currentDownloadSpeed_{0};

    std::atomic<int64_t> periodUpload_{0};
    std::atomic<int64_t> periodDownload_{0};

    // 用户与端口维度的未持久化流量缓存
    mutable std::mutex persistMutex_;
    std::map<int, int64_t> unpersistedUserUp_;
    std::map<int, int64_t> unpersistedUserDown_;
    std::map<int, int64_t> unpersistedPortUp_;
    std::map<int, int64_t> unpersistedPortDown_;

    mutable std::mutex historyMutex_;
    std::deque<RealtimeTrafficData> history_;
};
