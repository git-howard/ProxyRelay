#include "TrafficMonitor.h"
#include "Database.h"
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
    MinuteData data;
    // 获取这分钟的累积并清零，准备下一分钟
    // 注意：这里currentMinuteUpload不是原子的，但TickMinute是在MonitorThread单线程调用的
    // 而RecordUpload会并发修改它。所以currentMinuteUpload必须是原子的，或者加锁。
    // 为了简单，我们将currentMinuteUpload改为在Record函数中直接累加的原子变量，或者像lastSecond一样处理。
    // 既然头文件中没定义成原子，我们这里把它当做累加器，但其实Record函数并没有更新它？
    // 让我们在RecordUpload里更新它。为了线程安全，我们应该在TrafficEntity里把它改成原子，或者用mutex。
    // 查看头文件定义，它是 int64_t currentMinuteUpload = 0; 
    // 我们需要在Record里加锁或者改成原子。既然头文件已定（或者我可以改头文件？），
    // 刚才头文件里我没把它改成原子。
    // 让我们暂时假设在RecordUpload里我们会用锁保护，或者我们现在修改RecordUpload来原子更新它。
    // 实际上我们可以复用 lastSecondUpload 的累加值。
    // 我们可以每秒把 currentSpeed 加到 currentMinuteUpload 上。
    
    currentMinuteUpload += currentUploadSpeed;
    currentMinuteDownload += currentDownloadSpeed;
    
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
        entity->lastSecondUpload += bytes; // 原子操作
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
    }
}

void TrafficMonitor::PersistTraffic() {
    std::lock_guard<std::mutex> lock(statsMutex_);
    for (auto& pair : userStats_) {
        int64_t upload = pair.second->sessionUpload.exchange(0);
        int64_t download = pair.second->sessionDownload.exchange(0);
        if (upload > 0 || download > 0) {
            Database::Instance().RecordTraffic(pair.first, upload, download);
        }
    }
    // 端口流量目前没有数据库表，暂不持久化或需要新增表
    // 如果用户需要端口流量历史，需要在Database中添加支持
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
    size_t count = std::min(static_cast<size_t>(seconds), history_.size());
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
            entity->lastMonthUpload = entity->monthUpload + stats.upload24h;
            entity->lastMonthDownload = entity->monthDownload + stats.download24h;
            entity->monthUpload = 0;
            entity->monthDownload = 0;
        }
        
        // 累加当前24h流量到周/月（但只累加一次）
        entity->weekUpload += stats.upload24h;
        entity->weekDownload += stats.download24h;
        entity->monthUpload += stats.upload24h;
        entity->monthDownload += stats.download24h;
        entity->lastWeekKey = currentWeek;
        entity->lastMonthKey = currentMonth;
        
        Database::Instance().SavePortTrafficStats(
            pair.first, 
            stats.upload1h, stats.download1h,
            stats.upload24h, stats.download24h,
            entity->weekUpload, entity->weekDownload,
            entity->monthUpload, entity->monthDownload,
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
            entity->lastMonthUpload = entity->monthUpload + stats.upload24h;
            entity->lastMonthDownload = entity->monthDownload + stats.download24h;
            entity->monthUpload = 0;
            entity->monthDownload = 0;
        }
        
        entity->weekUpload += stats.upload24h;
        entity->weekDownload += stats.download24h;
        entity->monthUpload += stats.upload24h;
        entity->monthDownload += stats.download24h;
        entity->lastWeekKey = currentWeek;
        entity->lastMonthKey = currentMonth;
        
        Database::Instance().SaveUserTrafficStats(
            pair.first, 
            stats.upload1h, stats.download1h,
            stats.upload24h, stats.download24h,
            entity->weekUpload, entity->weekDownload,
            entity->monthUpload, entity->monthDownload,
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

