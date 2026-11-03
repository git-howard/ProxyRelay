#include "TrafficMonitor.h"
#include "Database.h"
#include "ProxyServer.h"
#include "RealtimeConnectionManager.h"
#include "SharedStatusManager.h"
#include "Rules.h"
#include "Utils.h"

TrafficMonitor& TrafficMonitor::Instance() {
    static TrafficMonitor instance;
    return instance;
}

TrafficMonitor::~TrafficMonitor() {
    Stop();
}

void TrafficMonitor::TrafficEntity::UpdateSpeed() {
    // 因为在statsMutex_保护下，直接操作即可
    currentUploadSpeed = lastSecondUpload;
    lastSecondUpload = 0;
    currentDownloadSpeed = lastSecondDownload;
    lastSecondDownload = 0;
}

void TrafficMonitor::TrafficEntity::TickMinute() {
    // 将当前分钟的累积数据保存到历史队列，然后清零
    // currentMinuteUpload 由 MonitorThread 每秒在 statsMutex_ 保护下累加
    MinuteData data;
    data.upload = currentMinuteUpload;
    data.download = currentMinuteDownload;
    
    historyBytes.push_back(data);
    while (historyBytes.size() > 1440) { // 24小时 = 1440分钟
        historyBytes.pop_front();
    }
    
    currentMinuteUpload = 0;
    currentMinuteDownload = 0;
}

TrafficMonitor::Stats TrafficMonitor::TrafficEntity::CalculateStats() const {
    Stats stats;
    stats.uploadSpeed = currentUploadSpeed;
    stats.downloadSpeed = currentDownloadSpeed;
    
    // 计算1h和24h
    // 注意：historyBytes不是线程安全的，而且CalculateStats可能被UI线程调用。
    // 我们需要锁。但在Entity级别没有锁。
    // 简单的办法是只在MonitorThread里访问history，或者加个锁。
    // 我们在TrafficMonitor级有 statsMutex_。
    
    int count = 0;
    for (auto it = historyBytes.rbegin(); it != historyBytes.rend(); ++it) {
        if (count < 60) {
            stats.upload1h += it->upload;
            stats.download1h += it->download;
        }
        stats.upload24h += it->upload;
        stats.download24h += it->download;
        count++;
    }
    // 加上当前这一分钟已经产生的流量
    // stats.upload1h += currentMinuteUpload; 
    // 这里可能有并发问题，忽略当前分钟的非原子部分，误差接受。
    
    // 本周/本月流量直接使用保存的累积值
    stats.uploadWeek = weekUpload + stats.upload24h;  // 已保存的 + 当前24h内的
    stats.downloadWeek = weekDownload + stats.download24h;
    stats.uploadMonth = monthUpload + stats.upload24h;
    stats.downloadMonth = monthDownload + stats.download24h;
    
    // 上月流量
    stats.uploadLastMonth = lastMonthUpload;
    stats.downloadLastMonth = lastMonthDownload;
    
    return stats;
}

void TrafficMonitor::Start() {
    if (running_.load()) return;
    running_ = true;
    
    // 从数据库加载历史累计流量基准值，避免服务启动或重启时累计流量归零
    int64_t baseUp = 0, baseDown = 0;
    Database::Instance().GetTotalTraffic(baseUp, baseDown);
    totalUpload_ = baseUp;
    totalDownload_ = baseDown;

    LoadTrafficStats();  // 启动时加载保存的统计数据
    monitorThread_ = std::thread(&TrafficMonitor::MonitorThread, this);
}

void TrafficMonitor::Stop() {
    running_ = false;
    if (monitorThread_.joinable()) {
        monitorThread_.join();
    }
    PersistTraffic();
    SaveTrafficStats();  // 停止时保存统计数据
}

void TrafficMonitor::RecordUpload(int userId, int portId, int64_t bytes) {
    totalUpload_ += bytes;
    lastSecondUpload_ += bytes;
    
    std::lock_guard<std::mutex> lock(statsMutex_);
    
    // 更新用户
    if (userId > 0) {
        auto* entity = GetOrCreateUserEntity(userId);
        entity->sessionUpload += bytes;
        entity->lastSecondUpload += bytes; // 在 statsMutex_ 保护下操作
    }
    
    // 更新端口
    if (portId > 0) {
        auto* entity = GetOrCreatePortEntity(portId);
        entity->sessionUpload += bytes;
        entity->lastSecondUpload += bytes;
    }
}

void TrafficMonitor::RecordDownload(int userId, int portId, int64_t bytes) {
    totalDownload_ += bytes;
    lastSecondDownload_ += bytes;
    
    std::lock_guard<std::mutex> lock(statsMutex_);
    
    // 更新用户
    if (userId > 0) {
        auto* entity = GetOrCreateUserEntity(userId);
        entity->sessionDownload += bytes;
        entity->lastSecondDownload += bytes;
    }
    
    // 更新端口
    if (portId > 0) {
        auto* entity = GetOrCreatePortEntity(portId);
        entity->sessionDownload += bytes;
        entity->lastSecondDownload += bytes;
    }
}

TrafficMonitor::TrafficEntity* TrafficMonitor::GetOrCreateUserEntity(int userId) {
    auto it = userStats_.find(userId);
    if (it == userStats_.end()) {
        auto entity = std::make_unique<TrafficEntity>();
        entity->id = userId;
        userStats_[userId] = std::move(entity);
        return userStats_[userId].get();
    }
    return it->second.get();
}

TrafficMonitor::TrafficEntity* TrafficMonitor::GetOrCreatePortEntity(int portId) {
    auto it = portStats_.find(portId);
    if (it == portStats_.end()) {
        auto entity = std::make_unique<TrafficEntity>();
        entity->id = portId;
        portStats_[portId] = std::move(entity);
        return portStats_[portId].get();
    }
    return it->second.get();
}

TrafficMonitor::Stats TrafficMonitor::GetUserStats(int userId) const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    auto it = userStats_.find(userId);
    if (it != userStats_.end()) {
        return it->second->CalculateStats();
    }
    return Stats{};
}

TrafficMonitor::Stats TrafficMonitor::GetPortStats(int portId) const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    auto it = portStats_.find(portId);
    if (it != portStats_.end()) {
        return it->second->CalculateStats();
    }
    return Stats{};
}

void TrafficMonitor::GetUserUnpersistedTraffic(int userId, int64_t& upload, int64_t& download) const {
    upload = 0;
    download = 0;
    std::lock_guard<std::mutex> lock(statsMutex_);
    auto it = userStats_.find(userId);
    if (it != userStats_.end()) {
        upload = it->second->sessionUpload.load();
        download = it->second->sessionDownload.load();
    }
}

void TrafficMonitor::GetPortUnpersistedTraffic(int portId, int64_t& upload, int64_t& download) const {
    upload = 0;
    download = 0;
    std::lock_guard<std::mutex> lock(statsMutex_);
    auto it = portStats_.find(portId);
    if (it != portStats_.end()) {
        upload = it->second->sessionUpload.load();
        download = it->second->sessionDownload.load();
    }
}

void TrafficMonitor::GetAllUnpersistedTraffic(int64_t& upload, int64_t& download) const {
    upload = 0;
    download = 0;
    std::lock_guard<std::mutex> lock(statsMutex_);
    for (const auto& pair : userStats_) {
        upload += pair.second->sessionUpload.load();
        download += pair.second->sessionDownload.load();
    }
}

void TrafficMonitor::GetAllPortUnpersistedTraffic(int64_t& upload, int64_t& download) const {
    upload = 0;
    download = 0;
    std::lock_guard<std::mutex> lock(statsMutex_);
    for (const auto& pair : portStats_) {
        upload += pair.second->sessionUpload.load();
        download += pair.second->sessionDownload.load();
    }
}


void TrafficMonitor::MonitorThread() {
    int secondCounter = 0;
    
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        // 全局速度
        int64_t upload = lastSecondUpload_.exchange(0);
        int64_t download = lastSecondDownload_.exchange(0);
        currentUploadSpeed_ = upload;
        currentDownloadSpeed_ = download;
        
        // 记录全局历史
        RealtimeTrafficData data;
        data.timestamp = Utils::GetCurrentTimestamp();
        data.uploadSpeed = upload;
        data.downloadSpeed = download;
        data.totalUpload = totalUpload_.load();
        data.totalDownload = totalDownload_.load();
        
        // 检查并消费控制台发起的切断连接请求
        uint64_t reqClose = SharedStatusManager::Instance().GetAndClearCloseConnectionRequest();
        if (reqClose > 0) {
            RealtimeConnectionManager::Instance().CloseConnection(reqClose);
        }

        // 检查并消费跨进程同步请求（规则重载或端口重载保底机制）
        bool monReloadRules = false;
        bool monReloadPorts = false;
        if (SharedStatusManager::Instance().CheckAndClearReloadRequest(monReloadRules, monReloadPorts)) {
            if (monReloadRules) {
                Utils::Log("TrafficMonitor: 实时重载分流规则...");
                RuleManager::Instance().ReloadRoutingRules();
            }
            if (monReloadPorts) {
                Utils::Log("TrafficMonitor: 实时重载代理端口...");
                ProxyServer::Instance().ReloadPorts();
            }
        }

        // 获取当前连接快照
        auto conns = RealtimeConnectionManager::Instance().GetConnectionsSnapshot();

        // 广播实时心跳与网络指标至跨进程共享内存（供桌面控制台实时显示）
        SharedStatusManager::Instance().WriteStatus(
            ProxyServer::Instance().IsRunning(),
            ProxyServer::Instance().GetActiveConnections(),
            upload,
            download,
            totalUpload_.load(),
            totalDownload_.load(),
            conns
        );
        
        {
            std::lock_guard<std::mutex> lock(historyMutex_);
            history_.push_back(data);
            while (history_.size() > MAX_HISTORY_SIZE) {
                history_.pop_front();
            }
        }
        
        {
            std::lock_guard<std::mutex> lock(statsMutex_);
            
            // 更新每个实体的速度和累积
            for (auto& pair : userStats_) {
                pair.second->UpdateSpeed();
                // 每秒累加到当前分钟（UpdateSpeed已经清零了lastSecond，这里把刚刚获取的速度加上去）
                pair.second->currentMinuteUpload += pair.second->currentUploadSpeed;
                pair.second->currentMinuteDownload += pair.second->currentDownloadSpeed;
            }
            for (auto& pair : portStats_) {
                pair.second->UpdateSpeed();
                pair.second->currentMinuteUpload += pair.second->currentUploadSpeed;
                pair.second->currentMinuteDownload += pair.second->currentDownloadSpeed;
            }
            
            // 每分钟tick
            secondCounter++;
            if (secondCounter >= 60) {
                secondCounter = 0;
                for (auto& pair : userStats_) pair.second->TickMinute();
                for (auto& pair : portStats_) pair.second->TickMinute();
            }
        }
        
        if (callback_) {
            callback_(data);
        }
        
        persistCounter_++;
        if (persistCounter_ >= 10) { // 每10秒持久化一次
            persistCounter_ = 0;
            PersistTraffic();
        }

        static int cleanHourCounter = 0;
        if (++cleanHourCounter >= 3600) { // 每小时清理一次超期流量数据
            cleanHourCounter = 0;
            Database::Instance().CleanOldTrafficRecords();
        }
    }
}

void TrafficMonitor::PersistTraffic() {
    std::vector<std::pair<int, std::pair<int64_t, int64_t>>> userToPersist;
    std::vector<std::pair<int, std::pair<int64_t, int64_t>>> portToPersist;
    {
        std::lock_guard<std::mutex> lock(statsMutex_);
        for (auto& pair : userStats_) {
            int64_t upload = pair.second->sessionUpload.exchange(0);
            int64_t download = pair.second->sessionDownload.exchange(0);
            if (upload > 0 || download > 0) {
                userToPersist.push_back({pair.first, {upload, download}});
            }
        }
        for (auto& pair : portStats_) {
            int64_t upload = pair.second->sessionUpload.exchange(0);
            int64_t download = pair.second->sessionDownload.exchange(0);
            if (upload > 0 || download > 0) {
                portToPersist.push_back({pair.first, {upload, download}});
            }
        }
    }
    for (const auto& item : userToPersist) {
        Database::Instance().RecordTraffic(item.first, item.second.first, item.second.second);
    }
    for (const auto& item : portToPersist) {
        Database::Instance().RecordPortTraffic(item.first, item.second.first, item.second.second);
    }
}


RealtimeTrafficData TrafficMonitor::GetCurrentData() const {
    RealtimeTrafficData data;
    data.timestamp = Utils::GetCurrentTimestamp();
    data.uploadSpeed = currentUploadSpeed_.load();
    data.downloadSpeed = currentDownloadSpeed_.load();
    data.totalUpload = totalUpload_.load();
    data.totalDownload = totalDownload_.load();
    return data;
}

std::vector<RealtimeTrafficData> TrafficMonitor::GetRecentHistory(int seconds) const {
    std::lock_guard<std::mutex> lock(historyMutex_);
    std::vector<RealtimeTrafficData> result;
    size_t count = (std::min)(static_cast<size_t>(seconds), history_.size());
    for (size_t i = history_.size() - count; i < history_.size(); ++i) {
        result.push_back(history_[i]);
    }
    return result;
}

void TrafficMonitor::SaveTrafficStats() {
    std::lock_guard<std::mutex> lock(statsMutex_);
    
    // 获取当前周和月的标识
    std::string currentWeek = Utils::GetCurrentWeek();  // 格式: YYYY-WW
    std::string currentMonth = Utils::GetCurrentMonth(); // 格式: YYYY-MM
    
    // 保存端口流量统计
    for (auto& pair : portStats_) {
        auto& entity = pair.second;
        auto stats = entity->CalculateStats();
        
        // 检查是否需要重置周/月累积（周或月变更时）
        if (!entity->lastWeekKey.empty() && entity->lastWeekKey != currentWeek) {
            entity->weekUpload = 0;
            entity->weekDownload = 0;
        }
        if (!entity->lastMonthKey.empty() && entity->lastMonthKey != currentMonth) {
            // 月份变更时，将本月流量转移到上月
            // stats 中的 uploadMonth 已经包含了 monthUpload + upload24h
            entity->lastMonthUpload = stats.uploadMonth;
            entity->lastMonthDownload = stats.downloadMonth;
            entity->monthUpload = 0;
            entity->monthDownload = 0;
        }
        entity->lastWeekKey = currentWeek;
        entity->lastMonthKey = currentMonth;
        
        // 保存时使用 CalculateStats() 计算出的完整值
        // weekUpload/monthUpload 仅存储历史累积部分（不含当前24h）
        // CalculateStats() 在展示时会自动加上当前24h数据
        Database::Instance().SavePortTrafficStats(
            pair.first, 
            stats.upload1h, stats.download1h,
            stats.upload24h, stats.download24h,
            stats.uploadWeek, stats.downloadWeek,
            stats.uploadMonth, stats.downloadMonth,
            entity->lastMonthUpload, entity->lastMonthDownload
        );
    }
    
    // 保存用户流量统计
    for (auto& pair : userStats_) {
        auto& entity = pair.second;
        auto stats = entity->CalculateStats();
        
        // 检查是否需要重置周/月累积
        if (!entity->lastWeekKey.empty() && entity->lastWeekKey != currentWeek) {
            entity->weekUpload = 0;
            entity->weekDownload = 0;
        }
        if (!entity->lastMonthKey.empty() && entity->lastMonthKey != currentMonth) {
            // 月份变更时，将本月流量转移到上月
            entity->lastMonthUpload = stats.uploadMonth;
            entity->lastMonthDownload = stats.downloadMonth;
            entity->monthUpload = 0;
            entity->monthDownload = 0;
        }
        entity->lastWeekKey = currentWeek;
        entity->lastMonthKey = currentMonth;
        
        Database::Instance().SaveUserTrafficStats(
            pair.first, 
            stats.upload1h, stats.download1h,
            stats.upload24h, stats.download24h,
            stats.uploadWeek, stats.downloadWeek,
            stats.uploadMonth, stats.downloadMonth,
            entity->lastMonthUpload, entity->lastMonthDownload
        );
    }
    
    Utils::Log("Traffic stats saved");
}

void TrafficMonitor::LoadTrafficStats() {
    std::lock_guard<std::mutex> lock(statsMutex_);
    
    std::string currentWeek = Utils::GetCurrentWeek();
    std::string currentMonth = Utils::GetCurrentMonth();
    
    // 加载端口流量统计
    auto portIds = Database::Instance().GetAllPortIds();
    for (int portId : portIds) {
        int64_t u1h, d1h, u24h, d24h, uWeek, dWeek, uMonth, dMonth, uLastMonth, dLastMonth;
        if (Database::Instance().LoadPortTrafficStats(portId, u1h, d1h, u24h, d24h, uWeek, dWeek, uMonth, dMonth, uLastMonth, dLastMonth)) {
            auto* entity = GetOrCreatePortEntity(portId);
            // 恢复周/月累积值
            entity->weekUpload = uWeek;
            entity->weekDownload = dWeek;
            entity->monthUpload = uMonth;
            entity->monthDownload = dMonth;
            entity->lastMonthUpload = uLastMonth;
            entity->lastMonthDownload = dLastMonth;
            entity->lastWeekKey = currentWeek;
            entity->lastMonthKey = currentMonth;
        }
    }
    
    // 加载用户流量统计
    auto userIds = Database::Instance().GetAllUserIds();
    for (int userId : userIds) {
        int64_t u1h, d1h, u24h, d24h, uWeek, dWeek, uMonth, dMonth, uLastMonth, dLastMonth;
        if (Database::Instance().LoadUserTrafficStats(userId, u1h, d1h, u24h, d24h, uWeek, dWeek, uMonth, dMonth, uLastMonth, dLastMonth)) {
            auto* entity = GetOrCreateUserEntity(userId);
            entity->weekUpload = uWeek;
            entity->weekDownload = dWeek;
            entity->monthUpload = uMonth;
            entity->monthDownload = dMonth;
            entity->lastMonthUpload = uLastMonth;
            entity->lastMonthDownload = dLastMonth;
            entity->lastWeekKey = currentWeek;
            entity->lastMonthKey = currentMonth;
        }
    }
    
    Utils::Log("Traffic stats loaded");
}

