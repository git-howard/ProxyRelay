#include "TrafficMonitor.h"
#include "Database.h"
#include "Utils.h"

TrafficMonitor& TrafficMonitor::Instance() {
    static TrafficMonitor instance;
    return instance;
}

TrafficMonitor::TrafficMonitor() = default;

TrafficMonitor::~TrafficMonitor() {
    Stop();
}

void TrafficMonitor::Start() {
    if (running_.load()) return;
    running_.store(true);
    workerThread_ = std::thread(&TrafficMonitor::MonitorLoop, this);
}

void TrafficMonitor::Stop() {
    if (!running_.load()) return;
    running_.store(false);
    if (workerThread_.joinable()) {
        workerThread_.join();
    }
    PersistTraffic();
}

void TrafficMonitor::RecordUpload(int userId, int portId, int64_t bytes) {
    if (bytes <= 0) return;
    totalUpload_.fetch_add(bytes);
    periodUpload_.fetch_add(bytes);

    if (userId > 0 || portId > 0) {
        std::lock_guard<std::mutex> lock(persistMutex_);
        if (userId > 0) unpersistedUserUp_[userId] += bytes;
        if (portId > 0) unpersistedPortUp_[portId] += bytes;
    }
}

void TrafficMonitor::RecordDownload(int userId, int portId, int64_t bytes) {
    if (bytes <= 0) return;
    totalDownload_.fetch_add(bytes);
    periodDownload_.fetch_add(bytes);

    if (userId > 0 || portId > 0) {
        std::lock_guard<std::mutex> lock(persistMutex_);
        if (userId > 0) unpersistedUserDown_[userId] += bytes;
        if (portId > 0) unpersistedPortDown_[portId] += bytes;
    }
}

RealtimeTrafficData TrafficMonitor::GetCurrentData() const {
    return {
        Utils::GetCurrentTimestamp(),
        currentUploadSpeed_.load(),
        currentDownloadSpeed_.load(),
        totalUpload_.load(),
        totalDownload_.load()
    };
}

std::vector<RealtimeTrafficData> TrafficMonitor::GetRecentHistory(int seconds) const {
    std::lock_guard<std::mutex> lock(historyMutex_);
    std::vector<RealtimeTrafficData> res;
    int count = std::min((int)history_.size(), seconds);
    res.reserve(count);
    for (auto it = history_.end() - count; it != history_.end(); ++it) {
        res.push_back(*it);
    }
    return res;
}

void TrafficMonitor::MonitorLoop() {
    int tickCount = 0;
    int cleanHourCounter = 0;
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        int64_t up = periodUpload_.exchange(0);
        int64_t down = periodDownload_.exchange(0);

        currentUploadSpeed_.store(up);
        currentDownloadSpeed_.store(down);

        RealtimeTrafficData data{
            Utils::GetCurrentTimestamp(),
            up,
            down,
            totalUpload_.load(),
            totalDownload_.load()
        };

        {
            std::lock_guard<std::mutex> lock(historyMutex_);
            history_.push_back(data);
            if (history_.size() > 120) {
                history_.pop_front();
            }
        }

        // 每 5 秒批量向数据库持久化一次用户与节点流量增量
        if (++tickCount >= 5) {
            tickCount = 0;
            PersistTraffic();
        }

        // 每小时定期执行一次超期流量自动清理
        if (++cleanHourCounter >= 3600) {
            cleanHourCounter = 0;
            Database::Instance().CleanOldTrafficRecords();
        }
    }
}

void TrafficMonitor::PersistTraffic() {
    std::map<int, int64_t> toSaveUp;
    std::map<int, int64_t> toSaveDown;
    std::map<int, int64_t> toSavePortUp;
    std::map<int, int64_t> toSavePortDown;
    {
        std::lock_guard<std::mutex> lock(persistMutex_);
        toSaveUp = std::move(unpersistedUserUp_);
        toSaveDown = std::move(unpersistedUserDown_);
        toSavePortUp = std::move(unpersistedPortUp_);
        toSavePortDown = std::move(unpersistedPortDown_);
    }

    for (const auto& kv : toSaveUp) {
        int uid = kv.first;
        int64_t uBytes = kv.second;
        int64_t dBytes = toSaveDown[uid];
        toSaveDown.erase(uid);
        Database::Instance().RecordTraffic(uid, uBytes, dBytes);
    }
    for (const auto& kv : toSaveDown) {
        Database::Instance().RecordTraffic(kv.first, 0, kv.second);
    }

    for (const auto& kv : toSavePortUp) {
        int pid = kv.first;
        int64_t uBytes = kv.second;
        int64_t dBytes = toSavePortDown[pid];
        toSavePortDown.erase(pid);
        Database::Instance().RecordPortTraffic(pid, uBytes, dBytes);
    }
    for (const auto& kv : toSavePortDown) {
        Database::Instance().RecordPortTraffic(kv.first, 0, kv.second);
    }
}

void TrafficMonitor::GetUserUnpersistedTraffic(int userId, int64_t& upload, int64_t& download) const {
    upload = 0;
    download = 0;
    if (userId <= 0) return;
    std::lock_guard<std::mutex> lock(persistMutex_);
    auto itU = unpersistedUserUp_.find(userId);
    if (itU != unpersistedUserUp_.end()) upload = itU->second;
    auto itD = unpersistedUserDown_.find(userId);
    if (itD != unpersistedUserDown_.end()) download = itD->second;
}
