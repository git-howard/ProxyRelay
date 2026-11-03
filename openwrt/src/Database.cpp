#include "Database.h"
#include "Utils.h"
#include "TrafficMonitor.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <map>
#include <ctime>
#include <algorithm>

Database& Database::Instance() {
    static Database instance;
    return instance;
}

Database::~Database() {
    Close();
}

bool Database::Initialize(const std::string& dbPath) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (db_ != nullptr) return true;

    int rc = sqlite3_open(dbPath.c_str(), &db_);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to open sqlite database: " << sqlite3_errmsg(db_) << std::endl;
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return false;
    }

    // 启用 WAL 模式提高读写并发性能
    char* err = nullptr;
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;", nullptr, nullptr, &err);
    if (err) sqlite3_free(err);

    bool ok = CreateTables();
    if (ok) {
        EnsureFallbackRule();
        DeduplicateProxyPorts();
        CleanOldTrafficRecords();
    }
    return ok;
}

void Database::Close() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool Database::CreateTables() {
    const char* schema = R"(
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT,
            allowed_ips TEXT DEFAULT '*',
            daily_limit INTEGER DEFAULT 0,
            monthly_limit INTEGER DEFAULT 0,
            enabled INTEGER DEFAULT 1,
            remark TEXT,
            expiry_date TEXT,
            allowed_targets TEXT DEFAULT '*',
            priority INTEGER DEFAULT 0,
            quota_reset_month TEXT,
            quota_offset_bytes INTEGER DEFAULT 0,
            quota_reset_date TEXT,
            daily_quota_offset_bytes INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS proxy_ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            listen_port INTEGER DEFAULT 0,
            upstream_type TEXT NOT NULL,
            upstream_host TEXT,
            upstream_port INTEGER DEFAULT 0,
            upstream_user TEXT,
            upstream_pass TEXT,
            enabled INTEGER DEFAULT 1,
            auto_check INTEGER DEFAULT 1,
            description TEXT,
            priority INTEGER DEFAULT 0,
            group_name TEXT DEFAULT '默认',
            xray_config TEXT,
            clash_config TEXT,
            clash_sub_id INTEGER DEFAULT 0,
            clash_node_name TEXT,
            allowed_targets TEXT DEFAULT '*',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS traffic_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            date TEXT NOT NULL,
            upload_bytes INTEGER DEFAULT 0,
            download_bytes INTEGER DEFAULT 0,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, date)
        );

        CREATE TABLE IF NOT EXISTS routing_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            priority INTEGER DEFAULT 0,
            match_type TEXT NOT NULL,
            match_value TEXT NOT NULL,
            proxy_id INTEGER DEFAULT 0,
            target_group TEXT,
            description TEXT,
            enabled INTEGER DEFAULT 1,
            is_fallback INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            raw_content TEXT,
            update_interval_days INTEGER DEFAULT 0,
            update_time TEXT DEFAULT '04:00',
            last_updated TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            upload_bytes INTEGER DEFAULT 0,
            download_bytes INTEGER DEFAULT 0,
            total_bytes INTEGER DEFAULT 0,
            expire_time TEXT,
            website_url TEXT,
            include_filter TEXT,
            exclude_filter TEXT,
            reset_cycle_days INTEGER DEFAULT 0,
            reset_start_date TEXT,
            cycle_offset_bytes INTEGER DEFAULT 0,
            last_reset_cycle INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE NOT NULL,
            reason TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            fail_count INTEGER DEFAULT 0,
            banned_until TEXT
        );

        CREATE TABLE IF NOT EXISTS configs (
            key TEXT PRIMARY KEY,
            value TEXT
        );

        CREATE TABLE IF NOT EXISTS whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE NOT NULL,
            remark TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS no_auth (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE NOT NULL,
            remark TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS port_traffic_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            port_id INTEGER NOT NULL,
            date TEXT NOT NULL,
            upload_bytes INTEGER DEFAULT 0,
            download_bytes INTEGER DEFAULT 0,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(port_id, date)
        );

        CREATE TABLE IF NOT EXISTS login_failures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            fail_time INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_login_failures_ip_time ON login_failures(ip, fail_time);
    )";

    char* errMsg = nullptr;
    int rc = sqlite3_exec(db_, schema, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error in CreateTables: " << (errMsg ? errMsg : "unknown") << std::endl;
        if (errMsg) sqlite3_free(errMsg);
        return false;
    }

    // 插入默认管理员或回退规则与自动封禁策略默认值 (5分钟内 错误10次 封禁1小时)
    sqlite3_exec(db_, "INSERT OR IGNORE INTO configs (key, value) VALUES ('inbound_proxy_type', 'all');", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "INSERT OR IGNORE INTO configs (key, value) VALUES ('auto_proxy_port', '1080');", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "INSERT OR IGNORE INTO configs (key, value) VALUES ('tproxy_enabled', '0');", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "INSERT OR IGNORE INTO configs (key, value) VALUES ('tproxy_port', '12345');", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "INSERT OR IGNORE INTO configs (key, value) VALUES ('ban_policy_enabled', '1');", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "INSERT OR IGNORE INTO configs (key, value) VALUES ('login_fail_window', '5');", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "INSERT OR IGNORE INTO configs (key, value) VALUES ('login_fail_limit', '10');", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "INSERT OR IGNORE INTO configs (key, value) VALUES ('ban_duration', '60');", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "INSERT OR IGNORE INTO configs (key, value) VALUES ('traffic_retention_days', '365');", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "INSERT OR IGNORE INTO configs (key, value) VALUES ('port_traffic_retention_days', '60');", nullptr, nullptr, nullptr);
    // 启动时清理历史自动封禁的临时黑名单记录
    sqlite3_exec(db_, "DELETE FROM blacklist WHERE reason LIKE '%自动封禁%' OR reason LIKE '%认证失败%';", nullptr, nullptr, nullptr);

    return true;
}

std::vector<UserInfo> Database::GetAllUsers() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<UserInfo> list;
    if (!db_) return list;

    const char* sql = "SELECT id, username, password, allowed_ips, daily_limit, monthly_limit, "
                      "enabled, remark, expiry_date, allowed_targets, priority, quota_reset_month, "
                      "quota_offset_bytes, quota_reset_date, daily_quota_offset_bytes, created_at, updated_at "
                      "FROM users ORDER BY priority ASC, id ASC;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            UserInfo u;
            u.id = sqlite3_column_int(stmt, 0);
            u.username = (const char*)sqlite3_column_text(stmt, 1) ? (const char*)sqlite3_column_text(stmt, 1) : "";
            u.password = (const char*)sqlite3_column_text(stmt, 2) ? (const char*)sqlite3_column_text(stmt, 2) : "";
            u.allowedIPs = (const char*)sqlite3_column_text(stmt, 3) ? (const char*)sqlite3_column_text(stmt, 3) : "*";
            u.dailyLimit = sqlite3_column_int64(stmt, 4);
            u.monthlyLimit = sqlite3_column_int64(stmt, 5);
            u.enabled = sqlite3_column_int(stmt, 6) != 0;
            u.remark = (const char*)sqlite3_column_text(stmt, 7) ? (const char*)sqlite3_column_text(stmt, 7) : "";
            u.expiryDate = (const char*)sqlite3_column_text(stmt, 8) ? (const char*)sqlite3_column_text(stmt, 8) : "";
            u.allowedTargets = (const char*)sqlite3_column_text(stmt, 9) ? (const char*)sqlite3_column_text(stmt, 9) : "*";
            u.priority = sqlite3_column_int(stmt, 10);
            u.quotaResetMonth = (const char*)sqlite3_column_text(stmt, 11) ? (const char*)sqlite3_column_text(stmt, 11) : "";
            u.quotaOffsetBytes = sqlite3_column_int64(stmt, 12);
            u.quotaResetDate = (const char*)sqlite3_column_text(stmt, 13) ? (const char*)sqlite3_column_text(stmt, 13) : "";
            u.dailyQuotaOffsetBytes = sqlite3_column_int64(stmt, 14);
            u.createdAt = (const char*)sqlite3_column_text(stmt, 15) ? (const char*)sqlite3_column_text(stmt, 15) : "";
            u.updatedAt = (const char*)sqlite3_column_text(stmt, 16) ? (const char*)sqlite3_column_text(stmt, 16) : "";
            list.push_back(u);
        }
        sqlite3_finalize(stmt);
    }
    return list;
}

bool Database::GetUserById(int id, UserInfo& user) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_) return false;
    const char* sql = "SELECT id, username, password, allowed_ips, daily_limit, monthly_limit, "
                      "enabled, remark, expiry_date, allowed_targets, priority, quota_reset_month, "
                      "quota_offset_bytes, quota_reset_date, daily_quota_offset_bytes FROM users WHERE id = ?;";
    sqlite3_stmt* stmt = nullptr;
    bool found = false;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, id);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            user.id = sqlite3_column_int(stmt, 0);
            user.username = (const char*)sqlite3_column_text(stmt, 1) ? (const char*)sqlite3_column_text(stmt, 1) : "";
            user.password = (const char*)sqlite3_column_text(stmt, 2) ? (const char*)sqlite3_column_text(stmt, 2) : "";
            user.allowedIPs = (const char*)sqlite3_column_text(stmt, 3) ? (const char*)sqlite3_column_text(stmt, 3) : "*";
            user.dailyLimit = sqlite3_column_int64(stmt, 4);
            user.monthlyLimit = sqlite3_column_int64(stmt, 5);
            user.enabled = sqlite3_column_int(stmt, 6) != 0;
            user.remark = (const char*)sqlite3_column_text(stmt, 7) ? (const char*)sqlite3_column_text(stmt, 7) : "";
            user.expiryDate = (const char*)sqlite3_column_text(stmt, 8) ? (const char*)sqlite3_column_text(stmt, 8) : "";
            user.allowedTargets = (const char*)sqlite3_column_text(stmt, 9) ? (const char*)sqlite3_column_text(stmt, 9) : "*";
            user.priority = sqlite3_column_int(stmt, 10);
            user.quotaResetMonth = (const char*)sqlite3_column_text(stmt, 11) ? (const char*)sqlite3_column_text(stmt, 11) : "";
            user.quotaOffsetBytes = sqlite3_column_int64(stmt, 12);
            user.quotaResetDate = (const char*)sqlite3_column_text(stmt, 13) ? (const char*)sqlite3_column_text(stmt, 13) : "";
            user.dailyQuotaOffsetBytes = sqlite3_column_int64(stmt, 14);
            found = true;
        }
        sqlite3_finalize(stmt);
    }
    return found;
}

bool Database::GetUserByUsername(const std::string& username, UserInfo& user) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_) return false;
    const char* sql = "SELECT id, username, password, allowed_ips, daily_limit, monthly_limit, "
                      "enabled, remark, expiry_date, allowed_targets, priority, quota_reset_month, "
                      "quota_offset_bytes, quota_reset_date, daily_quota_offset_bytes FROM users WHERE username = ?;";
    sqlite3_stmt* stmt = nullptr;
    bool found = false;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            user.id = sqlite3_column_int(stmt, 0);
            user.username = (const char*)sqlite3_column_text(stmt, 1) ? (const char*)sqlite3_column_text(stmt, 1) : "";
            user.password = (const char*)sqlite3_column_text(stmt, 2) ? (const char*)sqlite3_column_text(stmt, 2) : "";
            user.allowedIPs = (const char*)sqlite3_column_text(stmt, 3) ? (const char*)sqlite3_column_text(stmt, 3) : "*";
            user.dailyLimit = sqlite3_column_int64(stmt, 4);
            user.monthlyLimit = sqlite3_column_int64(stmt, 5);
            user.enabled = sqlite3_column_int(stmt, 6) != 0;
            user.remark = (const char*)sqlite3_column_text(stmt, 7) ? (const char*)sqlite3_column_text(stmt, 7) : "";
            user.expiryDate = (const char*)sqlite3_column_text(stmt, 8) ? (const char*)sqlite3_column_text(stmt, 8) : "";
            user.allowedTargets = (const char*)sqlite3_column_text(stmt, 9) ? (const char*)sqlite3_column_text(stmt, 9) : "*";
            user.priority = sqlite3_column_int(stmt, 10);
            user.quotaResetMonth = (const char*)sqlite3_column_text(stmt, 11) ? (const char*)sqlite3_column_text(stmt, 11) : "";
            user.quotaOffsetBytes = sqlite3_column_int64(stmt, 12);
            user.quotaResetDate = (const char*)sqlite3_column_text(stmt, 13) ? (const char*)sqlite3_column_text(stmt, 13) : "";
            user.dailyQuotaOffsetBytes = sqlite3_column_int64(stmt, 14);
            found = true;
        }
        sqlite3_finalize(stmt);
    }
    return found;
}

bool Database::GetUserByIP(const std::string& clientIP, UserInfo& user) {
    auto users = GetAllUsers();
    for (const auto& u : users) {
        if (!u.enabled) continue;
        bool hasIPRule = !u.allowedIPs.empty() && u.allowedIPs != "*";
        if (u.password.empty() && hasIPRule && Utils::IsIPAllowed(clientIP, u.allowedIPs)) {
            user = u;
            return true;
        }
    }
    return false;
}

bool Database::SaveUser(const UserInfo& user) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_) return false;

    int prio = user.priority;
    if (user.id > 0) {
        if (prio <= 0) {
            sqlite3_stmt* stmtP = nullptr;
            if (sqlite3_prepare_v2(db_, "SELECT priority FROM users WHERE id = ?;", -1, &stmtP, nullptr) == SQLITE_OK) {
                sqlite3_bind_int(stmtP, 1, user.id);
                if (sqlite3_step(stmtP) == SQLITE_ROW) {
                    prio = sqlite3_column_int(stmtP, 0);
                }
                sqlite3_finalize(stmtP);
            }
        }
        if (prio <= 0) {
            sqlite3_stmt* stmtMax = nullptr;
            if (sqlite3_prepare_v2(db_, "SELECT COALESCE(MAX(priority), 0) FROM users;", -1, &stmtMax, nullptr) == SQLITE_OK) {
                if (sqlite3_step(stmtMax) == SQLITE_ROW) {
                    prio = sqlite3_column_int(stmtMax, 0) + 1;
                }
                sqlite3_finalize(stmtMax);
            }
        }
        const char* sql = "UPDATE users SET username = ?, password = ?, allowed_ips = ?, daily_limit = ?, "
                          "monthly_limit = ?, enabled = ?, remark = ?, expiry_date = ?, allowed_targets = ?, "
                          "priority = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_text(stmt, 1, user.username.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, user.password.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, user.allowedIPs.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 4, user.dailyLimit);
        sqlite3_bind_int64(stmt, 5, user.monthlyLimit);
        sqlite3_bind_int(stmt, 6, user.enabled ? 1 : 0);
        sqlite3_bind_text(stmt, 7, user.remark.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 8, user.expiryDate.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 9, user.allowedTargets.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 10, prio);
        sqlite3_bind_int(stmt, 11, user.id);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return rc == SQLITE_DONE;
    } else {
        if (prio <= 0) {
            sqlite3_stmt* stmtMax = nullptr;
            if (sqlite3_prepare_v2(db_, "SELECT COALESCE(MAX(priority), 0) FROM users;", -1, &stmtMax, nullptr) == SQLITE_OK) {
                if (sqlite3_step(stmtMax) == SQLITE_ROW) {
                    prio = sqlite3_column_int(stmtMax, 0) + 1;
                }
                sqlite3_finalize(stmtMax);
            }
        }
        const char* sql = "INSERT INTO users (username, password, allowed_ips, daily_limit, monthly_limit, "
                          "enabled, remark, expiry_date, allowed_targets, priority) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_text(stmt, 1, user.username.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, user.password.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, user.allowedIPs.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 4, user.dailyLimit);
        sqlite3_bind_int64(stmt, 5, user.monthlyLimit);
        sqlite3_bind_int(stmt, 6, user.enabled ? 1 : 0);
        sqlite3_bind_text(stmt, 7, user.remark.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 8, user.expiryDate.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 9, user.allowedTargets.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 10, prio);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return rc == SQLITE_DONE;
    }
}

bool Database::DeleteUser(int id) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_) return false;
    std::string sql = "DELETE FROM users WHERE id = " + std::to_string(id) + ";";
    return sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK;
}

bool Database::ToggleUser(int id, bool enabled) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_) return false;
    std::string sql = "UPDATE users SET enabled = " + std::to_string(enabled ? 1 : 0) + " WHERE id = " + std::to_string(id) + ";";
    return sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK;
}

bool Database::MoveUserUp(int id) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_) return false;
    auto users = GetAllUsers();
    int idx = -1;
    for (size_t i = 0; i < users.size(); ++i) {
        if (users[i].id == id) { idx = (int)i; break; }
    }
    if (idx <= 0) return false;

    std::swap(users[idx], users[idx - 1]);
    for (size_t i = 0; i < users.size(); ++i) {
        int newPriority = (int)(i + 1);
        std::string sql = "UPDATE users SET priority = " + std::to_string(newPriority) + " WHERE id = " + std::to_string(users[i].id) + ";";
        sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, nullptr);
    }
    return true;
}

bool Database::MoveUserDown(int id) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_) return false;
    auto users = GetAllUsers();
    int idx = -1;
    for (size_t i = 0; i < users.size(); ++i) {
        if (users[i].id == id) { idx = (int)i; break; }
    }
    if (idx < 0 || idx >= (int)users.size() - 1) return false;

    std::swap(users[idx], users[idx + 1]);
    for (size_t i = 0; i < users.size(); ++i) {
        int newPriority = (int)(i + 1);
        std::string sql = "UPDATE users SET priority = " + std::to_string(newPriority) + " WHERE id = " + std::to_string(users[i].id) + ";";
        sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, nullptr);
    }
    return true;
}

bool Database::ResetUserTraffic(int userId) {
    // 1. 先将内存中未持久化的流量写入数据库，避免死锁并保证基准偏移精准
    TrafficMonitor::Instance().PersistTraffic();

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_ || userId <= 0) return false;

    std::string currentMonth = Utils::GetCurrentMonth();
    std::string currentDate = Utils::GetCurrentDate();

    // 2. 统计当前月份实际已发生流量（包括刚刚刷入的流量）
    int64_t monthlyRaw = 0;
    {
        std::string pattern = currentMonth + "%";
        const char* sql = "SELECT COALESCE(SUM(upload_bytes), 0) + COALESCE(SUM(download_bytes), 0) FROM traffic_records WHERE user_id = ? AND date LIKE ?;";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, userId);
            sqlite3_bind_text(stmt, 2, pattern.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                monthlyRaw = sqlite3_column_int64(stmt, 0);
            }
            sqlite3_finalize(stmt);
        }
    }

    // 3. 统计当前日期实际已发生流量
    int64_t dailyRaw = 0;
    {
        const char* sql = "SELECT COALESCE(SUM(upload_bytes), 0) + COALESCE(SUM(download_bytes), 0) FROM traffic_records WHERE user_id = ? AND date = ?;";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, userId);
            sqlite3_bind_text(stmt, 2, currentDate.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                dailyRaw = sqlite3_column_int64(stmt, 0);
            }
            sqlite3_finalize(stmt);
        }
    }

    // 4. 更新用户的配额重置基准偏移量，使当期已用额度归零并解除封禁
    // 重要说明：绝不删除 traffic_records，用户的总累计用量与30天趋势图等历史数据均完整保留！
    const char* sql = "UPDATE users SET quota_reset_month = ?, quota_offset_bytes = ?, "
                      "quota_reset_date = ?, daily_quota_offset_bytes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    sqlite3_bind_text(stmt, 1, currentMonth.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, monthlyRaw);
    sqlite3_bind_text(stmt, 3, currentDate.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, dailyRaw);
    sqlite3_bind_int(stmt, 5, userId);

    bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

// 端口管理
std::vector<ProxyPort> Database::GetAllProxyPorts() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<ProxyPort> list;
    if (!db_) return list;

    const char* sql = "SELECT id, listen_port, upstream_type, upstream_host, upstream_port, upstream_user, "
                      "upstream_pass, enabled, auto_check, description, priority, group_name, xray_config, "
                      "clash_config, clash_sub_id, clash_node_name, allowed_targets, created_at FROM proxy_ports "
                      "ORDER BY priority ASC, id ASC;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            ProxyPort p;
            p.id = sqlite3_column_int(stmt, 0);
            p.listenPort = sqlite3_column_int(stmt, 1);
            p.upstreamType = (const char*)sqlite3_column_text(stmt, 2) ? (const char*)sqlite3_column_text(stmt, 2) : "http";
            p.upstreamHost = (const char*)sqlite3_column_text(stmt, 3) ? (const char*)sqlite3_column_text(stmt, 3) : "";
            p.upstreamPort = sqlite3_column_int(stmt, 4);
            p.upstreamUser = (const char*)sqlite3_column_text(stmt, 5) ? (const char*)sqlite3_column_text(stmt, 5) : "";
            p.upstreamPass = (const char*)sqlite3_column_text(stmt, 6) ? (const char*)sqlite3_column_text(stmt, 6) : "";
            p.enabled = sqlite3_column_int(stmt, 7) != 0;
            p.autoCheck = sqlite3_column_int(stmt, 8) != 0;
            p.description = (const char*)sqlite3_column_text(stmt, 9) ? (const char*)sqlite3_column_text(stmt, 9) : "";
            p.priority = sqlite3_column_int(stmt, 10);
            p.groupName = (const char*)sqlite3_column_text(stmt, 11) ? (const char*)sqlite3_column_text(stmt, 11) : "默认";
            p.xrayConfig = (const char*)sqlite3_column_text(stmt, 12) ? (const char*)sqlite3_column_text(stmt, 12) : "";
            p.clashConfig = (const char*)sqlite3_column_text(stmt, 13) ? (const char*)sqlite3_column_text(stmt, 13) : "";
            p.clashSubscriptionId = sqlite3_column_int(stmt, 14);
            p.clashNodeName = (const char*)sqlite3_column_text(stmt, 15) ? (const char*)sqlite3_column_text(stmt, 15) : "";
            p.allowedTargets = (const char*)sqlite3_column_text(stmt, 16) ? (const char*)sqlite3_column_text(stmt, 16) : "*";
            p.createdAt = (const char*)sqlite3_column_text(stmt, 17) ? (const char*)sqlite3_column_text(stmt, 17) : "";
            list.push_back(p);
        }
        sqlite3_finalize(stmt);
    }
    return list;
}

bool Database::GetProxyPortById(int id, ProxyPort& port) {
    auto ports = GetAllProxyPorts();
    for (const auto& p : ports) {
        if (p.id == id) {
            port = p;
            return true;
        }
    }
    return false;
}

bool Database::SaveProxyPort(const ProxyPort& port) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_) return false;

    if (port.id > 0) {
        const char* sql = "UPDATE proxy_ports SET listen_port = ?, upstream_type = ?, upstream_host = ?, "
                          "upstream_port = ?, upstream_user = ?, upstream_pass = ?, enabled = ?, auto_check = ?, "
                          "description = ?, priority = ?, group_name = ?, xray_config = ?, clash_config = ?, "
                          "clash_sub_id = ?, clash_node_name = ?, allowed_targets = ? WHERE id = ?;";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_int(stmt, 1, port.listenPort);
        sqlite3_bind_text(stmt, 2, port.upstreamType.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, port.upstreamHost.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 4, port.upstreamPort);
        sqlite3_bind_text(stmt, 5, port.upstreamUser.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 6, port.upstreamPass.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 7, port.enabled ? 1 : 0);
        sqlite3_bind_int(stmt, 8, port.autoCheck ? 1 : 0);
        sqlite3_bind_text(stmt, 9, port.description.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 10, port.priority);
        sqlite3_bind_text(stmt, 11, port.groupName.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 12, port.xrayConfig.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 13, port.clashConfig.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 14, port.clashSubscriptionId);
        sqlite3_bind_text(stmt, 15, port.clashNodeName.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 16, port.allowedTargets.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 17, port.id);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return rc == SQLITE_DONE;
    } else {
        const char* sql = "INSERT INTO proxy_ports (listen_port, upstream_type, upstream_host, upstream_port, "
                          "upstream_user, upstream_pass, enabled, auto_check, description, priority, group_name, "
                          "xray_config, clash_config, clash_sub_id, clash_node_name, allowed_targets) "
                          "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_int(stmt, 1, port.listenPort);
        sqlite3_bind_text(stmt, 2, port.upstreamType.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, port.upstreamHost.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 4, port.upstreamPort);
        sqlite3_bind_text(stmt, 5, port.upstreamUser.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 6, port.upstreamPass.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 7, port.enabled ? 1 : 0);
        sqlite3_bind_int(stmt, 8, port.autoCheck ? 1 : 0);
        sqlite3_bind_text(stmt, 9, port.description.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 10, port.priority);
        sqlite3_bind_text(stmt, 11, port.groupName.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 12, port.xrayConfig.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 13, port.clashConfig.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 14, port.clashSubscriptionId);
        sqlite3_bind_text(stmt, 15, port.clashNodeName.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 16, port.allowedTargets.c_str(), -1, SQLITE_STATIC);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return rc == SQLITE_DONE;
    }
}

bool Database::DeleteProxyPort(int id) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_) return false;
    std::string sql = "DELETE FROM proxy_ports WHERE id = " + std::to_string(id) + ";";
    return sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK;
}

bool Database::ToggleProxyPort(int id, bool enabled) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_) return false;
    std::string sql = "UPDATE proxy_ports SET enabled = " + std::to_string(enabled ? 1 : 0) + " WHERE id = " + std::to_string(id) + ";";
    return sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK;
}

bool Database::MoveProxyPortUp(int id, const std::string& group) {
    auto ports = GetAllProxyPorts();
    std::vector<ProxyPort> filtered;
    for (const auto& p : ports) {
        if (group.empty() || p.groupName == group) filtered.push_back(p);
    }
    int idx = -1;
    for (size_t i = 0; i < filtered.size(); ++i) {
        if (filtered[i].id == id) { idx = i; break; }
    }
    if (idx <= 0) return false;
    std::swap(filtered[idx].priority, filtered[idx - 1].priority);
    if (filtered[idx].priority == filtered[idx - 1].priority) {
        filtered[idx - 1].priority -= 1;
    }
    SaveProxyPort(filtered[idx]);
    SaveProxyPort(filtered[idx - 1]);
    return true;
}

bool Database::MoveProxyPortDown(int id, const std::string& group) {
    auto ports = GetAllProxyPorts();
    std::vector<ProxyPort> filtered;
    for (const auto& p : ports) {
        if (group.empty() || p.groupName == group) filtered.push_back(p);
    }
    int idx = -1;
    for (size_t i = 0; i < filtered.size(); ++i) {
        if (filtered[i].id == id) { idx = i; break; }
    }
    if (idx < 0 || idx >= (int)filtered.size() - 1) return false;
    std::swap(filtered[idx].priority, filtered[idx + 1].priority);
    if (filtered[idx].priority == filtered[idx + 1].priority) {
        filtered[idx + 1].priority += 1;
    }
    SaveProxyPort(filtered[idx]);
    SaveProxyPort(filtered[idx + 1]);
    return true;
}

std::vector<std::string> Database::GetAllPortGroups() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<std::string> groups;
    if (!db_) return groups;
    const char* sql = "SELECT DISTINCT group_name FROM proxy_ports WHERE group_name IS NOT NULL AND group_name != '' ORDER BY group_name ASC;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* g = (const char*)sqlite3_column_text(stmt, 0);
            if (g) groups.push_back(g);
        }
        sqlite3_finalize(stmt);
    }
    return groups;
}

// 流量记录
bool Database::RecordTraffic(int userId, int64_t uploadBytes, int64_t downloadBytes) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_ || userId <= 0) return false;

    std::string today = Utils::GetCurrentDate();
    const char* sql = "INSERT INTO traffic_records (user_id, date, upload_bytes, download_bytes, updated_at) "
                      "VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP) "
                      "ON CONFLICT(user_id, date) DO UPDATE SET "
                      "upload_bytes = upload_bytes + excluded.upload_bytes, "
                      "download_bytes = download_bytes + excluded.download_bytes, "
                      "updated_at = CURRENT_TIMESTAMP;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_int(stmt, 1, userId);
    sqlite3_bind_text(stmt, 2, today.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, uploadBytes);
    sqlite3_bind_int64(stmt, 4, downloadBytes);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool Database::RecordPortTraffic(int portId, int64_t uploadBytes, int64_t downloadBytes) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_ || portId <= 0) return false;

    std::string today = Utils::GetCurrentDate();
    const char* sql = "INSERT INTO port_traffic_records (port_id, date, upload_bytes, download_bytes, updated_at) "
                      "VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP) "
                      "ON CONFLICT(port_id, date) DO UPDATE SET "
                      "upload_bytes = upload_bytes + excluded.upload_bytes, "
                      "download_bytes = download_bytes + excluded.download_bytes, "
                      "updated_at = CURRENT_TIMESTAMP;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_int(stmt, 1, portId);
    sqlite3_bind_text(stmt, 2, today.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, uploadBytes);
    sqlite3_bind_int64(stmt, 4, downloadBytes);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

void Database::CleanOldTrafficRecords(int userDays, int portDays) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_) return;

    if (userDays <= 0) {
        std::string sVal = GetConfig("traffic_retention_days", "365");
        userDays = std::atoi(sVal.c_str());
        if (userDays <= 0) userDays = 365;
    }
    if (portDays <= 0) {
        std::string sVal = GetConfig("port_traffic_retention_days", "60");
        portDays = std::atoi(sVal.c_str());
        if (portDays <= 0) portDays = 60;
    }

    std::string userCutoff = Utils::GetPastDate(userDays);
    std::string portCutoff = Utils::GetPastDate(portDays);

    sqlite3_stmt* stmt = nullptr;
    // 1. 清理超过保留期(如365天)的用户及全局流量历史
    if (sqlite3_prepare_v2(db_, "DELETE FROM traffic_records WHERE date < ?;", -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, userCutoff.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    // 2. 清理超过保留期(如60天)的节点流量明细
    stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM port_traffic_records WHERE date < ?;", -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, portCutoff.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
}

bool Database::GetTrafficStorageInfo(int64_t& recordCount, int64_t& totalBytes, int& dayCount) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    recordCount = 0;
    totalBytes = 0;
    dayCount = 0;
    if (!db_) return false;

    const char* sql = "SELECT count(*), coalesce(sum(length(user_id) + length(date) + length(upload_bytes) + length(download_bytes) + length(updated_at) + 32), 0), count(distinct date) FROM traffic_records;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            recordCount = sqlite3_column_int64(stmt, 0);
            totalBytes = sqlite3_column_int64(stmt, 1);
            dayCount = sqlite3_column_int(stmt, 2);
        }
        sqlite3_finalize(stmt);
        return true;
    }
    return false;
}

bool Database::GetPortTrafficStorageInfo(int64_t& recordCount, int64_t& totalBytes, int& dayCount) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    recordCount = 0;
    totalBytes = 0;
    dayCount = 0;
    if (!db_) return false;

    const char* sql = "SELECT count(*), coalesce(sum(length(port_id) + length(date) + length(upload_bytes) + length(download_bytes) + length(updated_at) + 32), 0), count(distinct date) FROM port_traffic_records;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            recordCount = sqlite3_column_int64(stmt, 0);
            totalBytes = sqlite3_column_int64(stmt, 1);
            dayCount = sqlite3_column_int(stmt, 2);
        }
        sqlite3_finalize(stmt);
        return true;
    }
    return false;
}

int64_t Database::GetUserMonthlyTraffic(int userId, const std::string& month) {
    if (userId <= 0) return 0;
    std::string m = month.empty() ? Utils::GetCurrentMonth() : month;
    std::string pattern = m + "%";
    int64_t total = 0;

    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (db_) {
            const char* sql = "SELECT COALESCE(SUM(upload_bytes), 0) + COALESCE(SUM(download_bytes), 0) FROM traffic_records WHERE user_id = ? AND date LIKE ?;";
            sqlite3_stmt* stmt = nullptr;
            if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, userId);
                sqlite3_bind_text(stmt, 2, pattern.c_str(), -1, SQLITE_STATIC);
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    total = sqlite3_column_int64(stmt, 0);
                }
                sqlite3_finalize(stmt);
            }

            if (m == Utils::GetCurrentMonth()) {
                UserInfo u;
                if (GetUserById(userId, u) && u.quotaResetMonth == m) {
                    total = std::max<int64_t>(0, total - u.quotaOffsetBytes);
                }
            }
        }
    }

    if (m == Utils::GetCurrentMonth()) {
        int64_t unpersistedUpload = 0, unpersistedDownload = 0;
        TrafficMonitor::Instance().GetUserUnpersistedTraffic(userId, unpersistedUpload, unpersistedDownload);
        total += (unpersistedUpload + unpersistedDownload);
    }

    return total;
}

int64_t Database::GetUserDailyTraffic(int userId, const std::string& date) {
    if (userId <= 0) return 0;
    std::string d = date.empty() ? Utils::GetCurrentDate() : date;
    int64_t total = 0;

    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (db_) {
            const char* sql = "SELECT COALESCE(upload_bytes, 0) + COALESCE(download_bytes, 0) FROM traffic_records WHERE user_id = ? AND date = ?;";
            sqlite3_stmt* stmt = nullptr;
            if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, userId);
                sqlite3_bind_text(stmt, 2, d.c_str(), -1, SQLITE_STATIC);
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    total = sqlite3_column_int64(stmt, 0);
                }
                sqlite3_finalize(stmt);
            }

            if (d == Utils::GetCurrentDate()) {
                UserInfo u;
                if (GetUserById(userId, u) && u.quotaResetDate == d) {
                    total = std::max<int64_t>(0, total - u.dailyQuotaOffsetBytes);
                }
            }
        }
    }

    if (d == Utils::GetCurrentDate()) {
        int64_t unpersistedUpload = 0, unpersistedDownload = 0;
        TrafficMonitor::Instance().GetUserUnpersistedTraffic(userId, unpersistedUpload, unpersistedDownload);
        total += (unpersistedUpload + unpersistedDownload);
    }

    return total;
}

int64_t Database::GetUserTotalTraffic(int userId) {
    if (userId <= 0) return 0;
    int64_t total = 0;

    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (db_) {
            const char* sql = "SELECT COALESCE(SUM(upload_bytes), 0) + COALESCE(SUM(download_bytes), 0) FROM traffic_records WHERE user_id = ?;";
            sqlite3_stmt* stmt = nullptr;
            if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, userId);
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    total = sqlite3_column_int64(stmt, 0);
                }
                sqlite3_finalize(stmt);
            }
        }
    }

    int64_t unpersistedUpload = 0, unpersistedDownload = 0;
    TrafficMonitor::Instance().GetUserUnpersistedTraffic(userId, unpersistedUpload, unpersistedDownload);
    total += (unpersistedUpload + unpersistedDownload);

    return total;
}

std::vector<DailyTrafficSummary> Database::GetDailyTrafficHistory(int days, int userId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<DailyTrafficSummary> result;
    if (!db_) return result;

    auto dateList = Utils::GetPastDates(days);
    for (const auto& d : dateList) {
        std::string sql;
        if (userId > 0) {
            sql = "SELECT SUM(upload_bytes), SUM(download_bytes) FROM traffic_records WHERE date = '" + d + "' AND user_id = " + std::to_string(userId) + ";";
        } else {
            sql = "SELECT SUM(upload_bytes), SUM(download_bytes) FROM traffic_records WHERE date = '" + d + "';";
        }

        sqlite3_stmt* stmt = nullptr;
        DailyTrafficSummary s;
        s.date = d;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                s.uploadBytes = sqlite3_column_int64(stmt, 0);
                s.downloadBytes = sqlite3_column_int64(stmt, 1);
                s.totalBytes = s.uploadBytes + s.downloadBytes;
            }
            sqlite3_finalize(stmt);
        }
        result.push_back(s);
    }
    return result;
}

std::vector<TrafficTrendItem> Database::GetTrafficTrend(const std::string& mode, int count, int userId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<TrafficTrendItem> result;
    if (!db_) return result;

    if (mode == "month") {
        if (count <= 0) count = 12;
        if (count > 36) count = 36;

        time_t now = time(nullptr);
        struct tm tm_now;
        localtime_r(&now, &tm_now);
        int curYear = tm_now.tm_year + 1900;
        int curMonth = tm_now.tm_mon + 1;

        struct MonthInfo {
            std::string ym;
            std::string label;
            std::string tooltip;
        };
        std::vector<MonthInfo> months;
        months.reserve(count);
        for (int i = count - 1; i >= 0; --i) {
            int totalMonths = curYear * 12 + (curMonth - 1) - i;
            int y = totalMonths / 12;
            int m = (totalMonths % 12) + 1;
            char buf[32] = {};
            snprintf(buf, sizeof(buf), "%04d-%02d", y, m);
            char lbl[16] = {};
            snprintf(lbl, sizeof(lbl), "%02d/%02d", y % 100, m);
            char tip[32] = {};
            snprintf(tip, sizeof(tip), "%04d年%02d月", y, m);
            months.push_back({buf, lbl, tip});
        }

        std::string startMonth = months.front().ym + "-01";
        std::string endMonth = months.back().ym + "-31";

        std::string sql;
        if (userId > 0) {
            sql = "SELECT substr(date, 1, 7) AS ym, SUM(upload_bytes), SUM(download_bytes) FROM traffic_records WHERE date >= '" + startMonth + "' AND date <= '" + endMonth + "' AND user_id = " + std::to_string(userId) + " GROUP BY ym;";
        } else {
            sql = "SELECT substr(date, 1, 7) AS ym, SUM(upload_bytes), SUM(download_bytes) FROM traffic_records WHERE date >= '" + startMonth + "' AND date <= '" + endMonth + "' GROUP BY ym;";
        }

        std::map<std::string, std::pair<int64_t, int64_t>> monthMap;
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* ym = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                if (ym) {
                    int64_t up = sqlite3_column_int64(stmt, 1);
                    int64_t down = sqlite3_column_int64(stmt, 2);
                    monthMap[ym] = {up, down};
                }
            }
            sqlite3_finalize(stmt);
        }

        for (const auto& mi : months) {
            TrafficTrendItem item;
            item.date = mi.ym;
            item.label = mi.label;
            item.tooltip = mi.tooltip;
            auto it = monthMap.find(mi.ym);
            if (it != monthMap.end()) {
                item.uploadBytes = it->second.first;
                item.downloadBytes = it->second.second;
                item.totalBytes = item.uploadBytes + item.downloadBytes;
            }
            result.push_back(item);
        }
    } else if (mode == "week") {
        if (count <= 0) count = 52;
        if (count > 104) count = 104;

        time_t now = time(nullptr);
        struct tm tm_now;
        localtime_r(&now, &tm_now);
        int daysFromMon = (tm_now.tm_wday == 0 ? 6 : tm_now.tm_wday - 1);

        tm_now.tm_hour = 12;
        tm_now.tm_min = 0;
        tm_now.tm_sec = 0;
        time_t currentNoon = mktime(&tm_now);
        time_t currentWeekMondayNoon = currentNoon - static_cast<time_t>(daysFromMon) * 86400;

        struct WeekInfo {
            std::string startDate;
            std::string endDate;
            std::string label;
            std::string tooltip;
            std::vector<std::string> days;
        };
        std::vector<WeekInfo> weeks;
        weeks.reserve(count);

        for (int i = count - 1; i >= 0; --i) {
            time_t wMon = currentWeekMondayNoon - static_cast<time_t>(i) * 7 * 86400;
            WeekInfo wi;
            wi.days.reserve(7);
            for (int d = 0; d < 7; ++d) {
                time_t tDay = wMon + static_cast<time_t>(d) * 86400;
                struct tm tm_d;
                localtime_r(&tDay, &tm_d);
                char buf[32] = {};
                strftime(buf, sizeof(buf), "%Y-%m-%d", &tm_d);
                wi.days.push_back(buf);
            }
            wi.startDate = wi.days.front();
            wi.endDate = wi.days.back();
            wi.label = wi.startDate.length() >= 5 ? wi.startDate.substr(5) : wi.startDate;
            std::replace(wi.label.begin(), wi.label.end(), '-', '/');
            wi.tooltip = wi.startDate + " ~ " + wi.endDate;
            weeks.push_back(wi);
        }

        std::string overallStart = weeks.front().startDate;
        std::string overallEnd = weeks.back().endDate;

        std::string sql;
        if (userId > 0) {
            sql = "SELECT date, SUM(upload_bytes), SUM(download_bytes) FROM traffic_records WHERE date >= '" + overallStart + "' AND date <= '" + overallEnd + "' AND user_id = " + std::to_string(userId) + " GROUP BY date;";
        } else {
            sql = "SELECT date, SUM(upload_bytes), SUM(download_bytes) FROM traffic_records WHERE date >= '" + overallStart + "' AND date <= '" + overallEnd + "' GROUP BY date;";
        }

        std::map<std::string, std::pair<int64_t, int64_t>> dayMap;
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* dStr = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                if (dStr) {
                    int64_t up = sqlite3_column_int64(stmt, 1);
                    int64_t down = sqlite3_column_int64(stmt, 2);
                    dayMap[dStr] = {up, down};
                }
            }
            sqlite3_finalize(stmt);
        }

        for (const auto& wi : weeks) {
            TrafficTrendItem item;
            item.date = wi.startDate + "~" + wi.endDate;
            item.label = wi.label;
            item.tooltip = wi.tooltip;
            for (const auto& dayStr : wi.days) {
                auto it = dayMap.find(dayStr);
                if (it != dayMap.end()) {
                    item.uploadBytes += it->second.first;
                    item.downloadBytes += it->second.second;
                }
            }
            item.totalBytes = item.uploadBytes + item.downloadBytes;
            result.push_back(item);
        }
    } else { // "day"
        if (count <= 0) count = 90;
        if (count > 365) count = 365;

        auto dateList = Utils::GetPastDates(count);
        if (dateList.empty()) return result;

        std::string overallStart = dateList.front();
        std::string overallEnd = dateList.back();

        std::string sql;
        if (userId > 0) {
            sql = "SELECT date, SUM(upload_bytes), SUM(download_bytes) FROM traffic_records WHERE date >= '" + overallStart + "' AND date <= '" + overallEnd + "' AND user_id = " + std::to_string(userId) + " GROUP BY date;";
        } else {
            sql = "SELECT date, SUM(upload_bytes), SUM(download_bytes) FROM traffic_records WHERE date >= '" + overallStart + "' AND date <= '" + overallEnd + "' GROUP BY date;";
        }

        std::map<std::string, std::pair<int64_t, int64_t>> dayMap;
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* dStr = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                if (dStr) {
                    int64_t up = sqlite3_column_int64(stmt, 1);
                    int64_t down = sqlite3_column_int64(stmt, 2);
                    dayMap[dStr] = {up, down};
                }
            }
            sqlite3_finalize(stmt);
        }

        for (const auto& d : dateList) {
            TrafficTrendItem item;
            item.date = d;
            item.label = (d.length() >= 5) ? d.substr(5) : d;
            item.tooltip = d;
            auto it = dayMap.find(d);
            if (it != dayMap.end()) {
                item.uploadBytes = it->second.first;
                item.downloadBytes = it->second.second;
                item.totalBytes = item.uploadBytes + item.downloadBytes;
            }
            result.push_back(item);
        }
    }

    return result;
}

std::vector<MonthlyTrafficSummary> Database::GetMonthlyTrafficHistory(int year, int userId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<MonthlyTrafficSummary> result;
    if (!db_) return result;

    if (year <= 0) {
        std::string cur = Utils::GetCurrentDate();
        year = std::atoi(cur.substr(0, 4).c_str());
    }

    for (int m = 1; m <= 12; ++m) {
        char buf[16] = {};
        snprintf(buf, sizeof(buf), "%04d-%02d", year, m);
        std::string mStr = buf;
        std::string pattern = mStr + "%";

        std::string sql;
        if (userId > 0) {
            sql = "SELECT SUM(upload_bytes), SUM(download_bytes) FROM traffic_records WHERE date LIKE '" + pattern + "' AND user_id = " + std::to_string(userId) + ";";
        } else {
            sql = "SELECT SUM(upload_bytes), SUM(download_bytes) FROM traffic_records WHERE date LIKE '" + pattern + "';";
        }

        MonthlyTrafficSummary ms;
        ms.month = mStr;
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                ms.uploadBytes = sqlite3_column_int64(stmt, 0);
                ms.downloadBytes = sqlite3_column_int64(stmt, 1);
                ms.totalBytes = ms.uploadBytes + ms.downloadBytes;
            }
            sqlite3_finalize(stmt);
        }
        result.push_back(ms);
    }
    return result;
}

// 路由规则
std::vector<RoutingRule> Database::GetAllRoutingRules() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<RoutingRule> list;
    if (!db_) return list;

    const char* sql = "SELECT id, priority, match_type, match_value, proxy_id, target_group, description, enabled, is_fallback, created_at "
                      "FROM routing_rules ORDER BY is_fallback ASC, priority ASC, id ASC;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            RoutingRule r;
            r.id = sqlite3_column_int(stmt, 0);
            r.priority = sqlite3_column_int(stmt, 1);
            r.matchType = (const char*)sqlite3_column_text(stmt, 2) ? (const char*)sqlite3_column_text(stmt, 2) : "domain";
            r.matchValue = (const char*)sqlite3_column_text(stmt, 3) ? (const char*)sqlite3_column_text(stmt, 3) : "";
            r.proxyId = sqlite3_column_int(stmt, 4);
            r.targetGroup = (const char*)sqlite3_column_text(stmt, 5) ? (const char*)sqlite3_column_text(stmt, 5) : "";
            r.description = (const char*)sqlite3_column_text(stmt, 6) ? (const char*)sqlite3_column_text(stmt, 6) : "";
            r.enabled = sqlite3_column_int(stmt, 7) != 0;
            r.isFallback = sqlite3_column_int(stmt, 8) != 0;
            r.createdAt = (const char*)sqlite3_column_text(stmt, 9) ? (const char*)sqlite3_column_text(stmt, 9) : "";
            list.push_back(r);
        }
        sqlite3_finalize(stmt);
    }
    return list;
}

bool Database::SaveRoutingRule(const RoutingRule& rule) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_) return false;

    if (rule.isFallback && rule.id <= 0) {
        int existingFallbackId = 0;
        sqlite3_stmt* stmtFb = nullptr;
        if (sqlite3_prepare_v2(db_, "SELECT id FROM routing_rules WHERE is_fallback = 1 LIMIT 1;", -1, &stmtFb, nullptr) == SQLITE_OK) {
            if (sqlite3_step(stmtFb) == SQLITE_ROW) {
                existingFallbackId = sqlite3_column_int(stmtFb, 0);
            }
            sqlite3_finalize(stmtFb);
        }
        if (existingFallbackId > 0) {
            RoutingRule rCopy = rule;
            rCopy.id = existingFallbackId;
            return SaveRoutingRule(rCopy);
        }
    }

    int prio = rule.priority;
    if (rule.id > 0) {
        if (prio <= 0) {
            sqlite3_stmt* stmtP = nullptr;
            if (sqlite3_prepare_v2(db_, "SELECT priority FROM routing_rules WHERE id = ?;", -1, &stmtP, nullptr) == SQLITE_OK) {
                sqlite3_bind_int(stmtP, 1, rule.id);
                if (sqlite3_step(stmtP) == SQLITE_ROW) {
                    prio = sqlite3_column_int(stmtP, 0);
                }
                sqlite3_finalize(stmtP);
            }
        }
        if (prio <= 0 && !rule.isFallback) {
            sqlite3_stmt* stmtMax = nullptr;
            if (sqlite3_prepare_v2(db_, "SELECT COALESCE(MAX(priority), 0) FROM routing_rules WHERE is_fallback = 0;", -1, &stmtMax, nullptr) == SQLITE_OK) {
                if (sqlite3_step(stmtMax) == SQLITE_ROW) {
                    prio = sqlite3_column_int(stmtMax, 0) + 1;
                }
                sqlite3_finalize(stmtMax);
            }
        }
        const char* sql = "UPDATE routing_rules SET priority = ?, match_type = ?, match_value = ?, "
                          "proxy_id = ?, target_group = ?, description = ?, enabled = ?, is_fallback = ? WHERE id = ?;";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_int(stmt, 1, prio);
        sqlite3_bind_text(stmt, 2, rule.matchType.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, rule.matchValue.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 4, rule.proxyId);
        sqlite3_bind_text(stmt, 5, rule.targetGroup.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 6, rule.description.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 7, rule.enabled ? 1 : 0);
        sqlite3_bind_int(stmt, 8, rule.isFallback ? 1 : 0);
        sqlite3_bind_int(stmt, 9, rule.id);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return rc == SQLITE_DONE;
    } else {
        if (rule.isFallback) {
            prio = 999999;
        } else if (prio <= 0) {
            sqlite3_stmt* stmtMax = nullptr;
            if (sqlite3_prepare_v2(db_, "SELECT COALESCE(MAX(priority), 0) FROM routing_rules WHERE is_fallback = 0;", -1, &stmtMax, nullptr) == SQLITE_OK) {
                if (sqlite3_step(stmtMax) == SQLITE_ROW) {
                    prio = sqlite3_column_int(stmtMax, 0) + 1;
                }
                sqlite3_finalize(stmtMax);
            }
        }
        const char* sql = "INSERT INTO routing_rules (priority, match_type, match_value, proxy_id, target_group, description, enabled, is_fallback) "
                          "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_int(stmt, 1, prio);
        sqlite3_bind_text(stmt, 2, rule.matchType.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, rule.matchValue.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 4, rule.proxyId);
        sqlite3_bind_text(stmt, 5, rule.targetGroup.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 6, rule.description.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 7, rule.enabled ? 1 : 0);
        sqlite3_bind_int(stmt, 8, rule.isFallback ? 1 : 0);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return rc == SQLITE_DONE;
    }
}

bool Database::DeleteRoutingRule(int id) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_) return false;
    std::string sql = "DELETE FROM routing_rules WHERE id = " + std::to_string(id) + ";";
    return sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK;
}

bool Database::ToggleRoutingRule(int id, bool enabled) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_) return false;
    std::string sql = "UPDATE routing_rules SET enabled = " + std::to_string(enabled ? 1 : 0) + " WHERE id = " + std::to_string(id) + ";";
    return sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK;
}

bool Database::MoveRoutingRuleUp(int id) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_) return false;
    auto rules = GetAllRoutingRules();
    int idx = -1;
    for (size_t i = 0; i < rules.size(); ++i) {
        if (rules[i].id == id) { idx = (int)i; break; }
    }
    if (idx <= 0 || rules[idx].isFallback) return false;

    std::swap(rules[idx], rules[idx - 1]);
    int prio = 1;
    for (size_t i = 0; i < rules.size(); ++i) {
        if (!rules[i].isFallback) {
            std::string sql = "UPDATE routing_rules SET priority = " + std::to_string(prio++) + " WHERE id = " + std::to_string(rules[i].id) + ";";
            sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, nullptr);
        }
    }
    sqlite3_exec(db_, "UPDATE routing_rules SET priority = 999999 WHERE is_fallback = 1;", nullptr, nullptr, nullptr);
    return true;
}

bool Database::MoveRoutingRuleDown(int id) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_) return false;
    auto rules = GetAllRoutingRules();
    int idx = -1;
    for (size_t i = 0; i < rules.size(); ++i) {
        if (rules[i].id == id) { idx = (int)i; break; }
    }
    if (idx < 0 || idx >= (int)rules.size() - 1 || rules[idx].isFallback) return false;
    if (rules[idx + 1].isFallback) return false;

    std::swap(rules[idx], rules[idx + 1]);
    int prio = 1;
    for (size_t i = 0; i < rules.size(); ++i) {
        if (!rules[i].isFallback) {
            std::string sql = "UPDATE routing_rules SET priority = " + std::to_string(prio++) + " WHERE id = " + std::to_string(rules[i].id) + ";";
            sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, nullptr);
        }
    }
    sqlite3_exec(db_, "UPDATE routing_rules SET priority = 999999 WHERE is_fallback = 1;", nullptr, nullptr, nullptr);
    return true;
}

// 订阅管理
std::vector<ClashSubscription> Database::GetAllSubscriptions() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<ClashSubscription> list;
    if (!db_) return list;

    const char* sql = "SELECT id, name, url, raw_content, update_interval_days, update_time, last_updated, "
                      "created_at, upload_bytes, download_bytes, total_bytes, expire_time, website_url, "
                      "include_filter, exclude_filter, reset_cycle_days, reset_start_date, cycle_offset_bytes, last_reset_cycle FROM subscriptions;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            ClashSubscription s;
            s.id = sqlite3_column_int(stmt, 0);
            s.name = (const char*)sqlite3_column_text(stmt, 1) ? (const char*)sqlite3_column_text(stmt, 1) : "";
            s.url = (const char*)sqlite3_column_text(stmt, 2) ? (const char*)sqlite3_column_text(stmt, 2) : "";
            s.rawContent = (const char*)sqlite3_column_text(stmt, 3) ? (const char*)sqlite3_column_text(stmt, 3) : "";
            s.updateIntervalDays = sqlite3_column_int(stmt, 4);
            s.updateTime = (const char*)sqlite3_column_text(stmt, 5) ? (const char*)sqlite3_column_text(stmt, 5) : "04:00";
            s.lastUpdated = (const char*)sqlite3_column_text(stmt, 6) ? (const char*)sqlite3_column_text(stmt, 6) : "";
            s.createdAt = (const char*)sqlite3_column_text(stmt, 7) ? (const char*)sqlite3_column_text(stmt, 7) : "";
            s.uploadBytes = sqlite3_column_int64(stmt, 8);
            s.downloadBytes = sqlite3_column_int64(stmt, 9);
            s.totalBytes = sqlite3_column_int64(stmt, 10);
            s.expireTime = (const char*)sqlite3_column_text(stmt, 11) ? (const char*)sqlite3_column_text(stmt, 11) : "";
            s.websiteUrl = (const char*)sqlite3_column_text(stmt, 12) ? (const char*)sqlite3_column_text(stmt, 12) : "";
            s.includeFilter = (const char*)sqlite3_column_text(stmt, 13) ? (const char*)sqlite3_column_text(stmt, 13) : "";
            s.excludeFilter = (const char*)sqlite3_column_text(stmt, 14) ? (const char*)sqlite3_column_text(stmt, 14) : "";
            s.resetCycleDays = sqlite3_column_int(stmt, 15);
            s.resetStartDate = (const char*)sqlite3_column_text(stmt, 16) ? (const char*)sqlite3_column_text(stmt, 16) : "";
            s.cycleOffsetBytes = sqlite3_column_int64(stmt, 17);
            s.lastResetCycle = sqlite3_column_int(stmt, 18);
            list.push_back(s);
        }
        sqlite3_finalize(stmt);
    }
    return list;
}

bool Database::GetSubscriptionById(int id, ClashSubscription& sub) {
    auto subs = GetAllSubscriptions();
    for (const auto& s : subs) {
        if (s.id == id) {
            sub = s;
            return true;
        }
    }
    return false;
}

bool Database::SaveSubscription(ClashSubscription& sub) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_) return false;

    if (sub.id > 0) {
        const char* sql = "UPDATE subscriptions SET name = ?, url = ?, raw_content = ?, update_interval_days = ?, "
                          "update_time = ?, last_updated = ?, upload_bytes = ?, download_bytes = ?, total_bytes = ?, "
                          "expire_time = ?, website_url = ?, include_filter = ?, exclude_filter = ?, reset_cycle_days = ?, "
                          "reset_start_date = ?, cycle_offset_bytes = ?, last_reset_cycle = ? WHERE id = ?;";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_text(stmt, 1, sub.name.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, sub.url.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, sub.rawContent.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 4, sub.updateIntervalDays);
        sqlite3_bind_text(stmt, 5, sub.updateTime.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 6, sub.lastUpdated.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 7, sub.uploadBytes);
        sqlite3_bind_int64(stmt, 8, sub.downloadBytes);
        sqlite3_bind_int64(stmt, 9, sub.totalBytes);
        sqlite3_bind_text(stmt, 10, sub.expireTime.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 11, sub.websiteUrl.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 12, sub.includeFilter.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 13, sub.excludeFilter.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 14, sub.resetCycleDays);
        sqlite3_bind_text(stmt, 15, sub.resetStartDate.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 16, sub.cycleOffsetBytes);
        sqlite3_bind_int(stmt, 17, sub.lastResetCycle);
        sqlite3_bind_int(stmt, 18, sub.id);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return rc == SQLITE_DONE;
    } else {
        const char* sql = "INSERT INTO subscriptions (name, url, raw_content, update_interval_days, update_time, "
                          "last_updated, upload_bytes, download_bytes, total_bytes, expire_time, website_url, "
                          "include_filter, exclude_filter, reset_cycle_days, reset_start_date, cycle_offset_bytes, last_reset_cycle) "
                          "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_text(stmt, 1, sub.name.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, sub.url.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, sub.rawContent.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 4, sub.updateIntervalDays);
        sqlite3_bind_text(stmt, 5, sub.updateTime.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 6, sub.lastUpdated.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 7, sub.uploadBytes);
        sqlite3_bind_int64(stmt, 8, sub.downloadBytes);
        sqlite3_bind_int64(stmt, 9, sub.totalBytes);
        sqlite3_bind_text(stmt, 10, sub.expireTime.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 11, sub.websiteUrl.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 12, sub.includeFilter.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 13, sub.excludeFilter.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 14, sub.resetCycleDays);
        sqlite3_bind_text(stmt, 15, sub.resetStartDate.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 16, sub.cycleOffsetBytes);
        sqlite3_bind_int(stmt, 17, sub.lastResetCycle);
        int rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) {
            sub.id = (int)sqlite3_last_insert_rowid(db_);
        }
        sqlite3_finalize(stmt);
        return rc == SQLITE_DONE;
    }
}

bool Database::DeleteSubscription(int id) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_) return false;
    std::string sql = "DELETE FROM subscriptions WHERE id = " + std::to_string(id) + ";";
    return sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK;
}

bool Database::DeletePortsBySubscriptionId(int subId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_) return false;
    std::string sql = "DELETE FROM proxy_ports WHERE clash_sub_id = " + std::to_string(subId) + ";";
    return sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK;
}

std::vector<ProxyPort> Database::GetPortsBySubscriptionId(int subId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<ProxyPort> ports;
    if (!db_) return ports;

    const char* sql = "SELECT id, listen_port, upstream_type, upstream_host, upstream_port, upstream_user, "
                      "upstream_pass, enabled, auto_check, description, priority, group_name, xray_config, "
                      "clash_config, clash_sub_id, clash_node_name, allowed_targets, created_at FROM proxy_ports "
                      "WHERE clash_sub_id = ? ORDER BY priority ASC, id ASC;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, subId);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            ProxyPort p;
            p.id = sqlite3_column_int(stmt, 0);
            p.listenPort = sqlite3_column_int(stmt, 1);
            p.upstreamType = (const char*)sqlite3_column_text(stmt, 2) ? (const char*)sqlite3_column_text(stmt, 2) : "clash";
            p.upstreamHost = (const char*)sqlite3_column_text(stmt, 3) ? (const char*)sqlite3_column_text(stmt, 3) : "";
            p.upstreamPort = sqlite3_column_int(stmt, 4);
            p.upstreamUser = (const char*)sqlite3_column_text(stmt, 5) ? (const char*)sqlite3_column_text(stmt, 5) : "";
            p.upstreamPass = (const char*)sqlite3_column_text(stmt, 6) ? (const char*)sqlite3_column_text(stmt, 6) : "";
            p.enabled = sqlite3_column_int(stmt, 7) != 0;
            p.autoCheck = sqlite3_column_int(stmt, 8) != 0;
            p.description = (const char*)sqlite3_column_text(stmt, 9) ? (const char*)sqlite3_column_text(stmt, 9) : "";
            p.priority = sqlite3_column_int(stmt, 10);
            p.groupName = (const char*)sqlite3_column_text(stmt, 11) ? (const char*)sqlite3_column_text(stmt, 11) : "默认";
            p.xrayConfig = (const char*)sqlite3_column_text(stmt, 12) ? (const char*)sqlite3_column_text(stmt, 12) : "";
            p.clashConfig = (const char*)sqlite3_column_text(stmt, 13) ? (const char*)sqlite3_column_text(stmt, 13) : "";
            p.clashSubscriptionId = sqlite3_column_int(stmt, 14);
            p.clashNodeName = (const char*)sqlite3_column_text(stmt, 15) ? (const char*)sqlite3_column_text(stmt, 15) : "";
            p.allowedTargets = (const char*)sqlite3_column_text(stmt, 16) ? (const char*)sqlite3_column_text(stmt, 16) : "*";
            p.createdAt = (const char*)sqlite3_column_text(stmt, 17) ? (const char*)sqlite3_column_text(stmt, 17) : "";
            ports.push_back(p);
        }
        sqlite3_finalize(stmt);
    }
    return ports;
}

int Database::DeduplicateProxyPorts() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto ports = GetAllProxyPorts();
    std::map<std::string, int> seenKeyToFirstId;
    std::vector<int> duplicateIds;

    for (const auto& p : ports) {
        std::string key;
        if (p.listenPort > 0) {
            key = "listen:" + std::to_string(p.listenPort);
        } else if (!p.clashNodeName.empty() && p.clashSubscriptionId > 0) {
            key = "sub:" + std::to_string(p.clashSubscriptionId) + ":" + p.clashNodeName;
        } else if (!p.upstreamHost.empty() && p.upstreamPort > 0) {
            key = "upstream:" + p.upstreamType + ":" + p.upstreamHost + ":" + std::to_string(p.upstreamPort) + ":" + p.groupName;
        } else {
            key = "desc:" + p.description + ":" + p.groupName;
        }

        if (seenKeyToFirstId.find(key) != seenKeyToFirstId.end()) {
            duplicateIds.push_back(p.id);
        } else {
            seenKeyToFirstId[key] = p.id;
        }
    }

    for (int dupId : duplicateIds) {
        std::string sql = "DELETE FROM proxy_ports WHERE id = " + std::to_string(dupId) + ";";
        sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, nullptr);
    }
    return (int)duplicateIds.size();
}

// 黑名单
std::vector<BlacklistItem> Database::GetBlacklist() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<BlacklistItem> list;
    if (!db_) return list;
    const char* sql = "SELECT id, ip, reason, created_at, fail_count, banned_until FROM blacklist ORDER BY id DESC;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            BlacklistItem b;
            b.id = sqlite3_column_int(stmt, 0);
            b.ip = (const char*)sqlite3_column_text(stmt, 1) ? (const char*)sqlite3_column_text(stmt, 1) : "";
            b.reason = (const char*)sqlite3_column_text(stmt, 2) ? (const char*)sqlite3_column_text(stmt, 2) : "";
            b.createdAt = (const char*)sqlite3_column_text(stmt, 3) ? (const char*)sqlite3_column_text(stmt, 3) : "";
            b.failCount = sqlite3_column_int(stmt, 4);
            b.bannedUntil = (const char*)sqlite3_column_text(stmt, 5) ? (const char*)sqlite3_column_text(stmt, 5) : "";
            list.push_back(b);
        }
        sqlite3_finalize(stmt);
    }
    return list;
}

bool Database::AddBlacklist(const std::string& ip, const std::string& reason) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_ || ip.empty()) return false;
    const char* sql = "INSERT OR REPLACE INTO blacklist (ip, reason, fail_count) VALUES (?, ?, 5);";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, reason.c_str(), -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool Database::RemoveBlacklist(const std::string& ip) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_ || ip.empty()) return false;
    const char* sql = "DELETE FROM blacklist WHERE ip = ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool Database::RemoveBlacklistById(int id) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_ || id <= 0) return false;
    std::string sql = "DELETE FROM blacklist WHERE id = " + std::to_string(id) + ";";
    return sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK;
}

Database::BanPolicy Database::GetBanPolicy() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    BanPolicy p;
    p.enabled = (GetConfig("ban_policy_enabled", "1") != "0");
    p.windowMinutes = std::atoi(GetConfig("login_fail_window", "5").c_str());
    p.maxFailures = std::atoi(GetConfig("login_fail_limit", "10").c_str());
    p.banMinutes = std::atoi(GetConfig("ban_duration", "60").c_str());
    if (p.windowMinutes <= 0) p.windowMinutes = 5;
    if (p.maxFailures <= 0) p.maxFailures = 10;
    if (p.banMinutes <= 0) p.banMinutes = 60;
    return p;
}

bool Database::SaveBanPolicy(const BanPolicy& policy) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    SetConfig("ban_policy_enabled", policy.enabled ? "1" : "0");
    SetConfig("login_fail_window", std::to_string(std::max(1, policy.windowMinutes)));
    SetConfig("login_fail_limit", std::to_string(std::max(1, policy.maxFailures)));
    SetConfig("ban_duration", std::to_string(std::max(1, policy.banMinutes)));
    return true;
}

bool Database::ClearAutoBans() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_) return false;
    sqlite3_exec(db_, "DELETE FROM login_failures;", nullptr, nullptr, nullptr);
    const char* sql = "DELETE FROM blacklist WHERE reason LIKE '%自动封禁%' OR reason LIKE '%连续认证失败%' OR reason LIKE '%认证失败%';";
    return sqlite3_exec(db_, sql, nullptr, nullptr, nullptr) == SQLITE_OK;
}

bool Database::IsIPBanned(const std::string& ip) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_ || ip.empty()) return false;
    // 永远不封禁本地回环和网关自身地址
    if (ip == "127.0.0.1" || ip == "localhost" || ip == "::1") return false;

    const char* sql = "SELECT id, banned_until, fail_count, reason FROM blacklist WHERE ip = ?;";
    sqlite3_stmt* stmt = nullptr;
    bool banned = false;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* until = (const char*)sqlite3_column_text(stmt, 1);
            const char* reason = (const char*)sqlite3_column_text(stmt, 3);
            std::string reasonStr = reason ? reason : "";

            bool isAutoBan = (reasonStr.find("自动封禁") != std::string::npos ||
                              reasonStr.find("连续认证失败") != std::string::npos ||
                              reasonStr.find("认证失败") != std::string::npos);

            if (isAutoBan) {
                // 内网局域网地址永远不触发自动封禁拦截，防止用户本地测试或输入失误导致阻断
                if (Utils::IsPrivateIP(ip)) {
                    banned = false;
                } else if (until && strlen(until) > 0) {
                    banned = (std::string(until) > Utils::GetCurrentDateTime());
                }
            } else {
                // 手动添加的黑名单
                if (until && strlen(until) > 0) {
                    banned = (std::string(until) > Utils::GetCurrentDateTime());
                } else {
                    banned = true;
                }
            }
        }
        sqlite3_finalize(stmt);
    }
    return banned;
}

void Database::RecordAuthFailure(const std::string& ip) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    // 内网私有地址不计入暴力破解自动封禁，防止本地主机被误封锁
    if (!db_ || ip.empty() || Utils::IsPrivateIP(ip)) return;

    BanPolicy policy = GetBanPolicy();
    if (!policy.enabled) return;

    int64_t nowSec = std::time(nullptr);

    // 1. 记录本次失败记录
    const char* insertSql = "INSERT INTO login_failures (ip, fail_time) VALUES (?, ?);";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, insertSql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 2, nowSec);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    // 2. 统计滑动窗口内的连续失败次数
    int64_t windowStart = nowSec - (policy.windowMinutes * 60);
    int failCount = 0;
    const char* countSql = "SELECT COUNT(*) FROM login_failures WHERE ip = ? AND fail_time >= ?;";
    if (sqlite3_prepare_v2(db_, countSql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 2, windowStart);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            failCount = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    // 3. 达到阈值时触发自动封禁
    if (failCount >= policy.maxFailures) {
        std::string bannedUntil = Utils::FormatTime(nowSec + (policy.banMinutes * 60));
        std::string nowStr = Utils::GetCurrentDateTime();
        std::string reason = "在" + std::to_string(policy.windowMinutes) + "分钟内连续认证失败达到" +
                             std::to_string(failCount) + "次 (封禁" + std::to_string(policy.banMinutes) + "分钟)";

        const char* banSql = R"(
            INSERT INTO blacklist (ip, reason, fail_count, banned_until, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET 
                reason = excluded.reason,
                fail_count = excluded.fail_count,
                banned_until = excluded.banned_until,
                created_at = excluded.created_at;
        )";
        if (sqlite3_prepare_v2(db_, banSql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, reason.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_int(stmt, 3, failCount);
            sqlite3_bind_text(stmt, 4, bannedUntil.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 5, nowStr.c_str(), -1, SQLITE_STATIC);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }

        // 清理该 IP 的历史失败记录，防止重复触发
        const char* cleanSql = "DELETE FROM login_failures WHERE ip = ?;";
        if (sqlite3_prepare_v2(db_, cleanSql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_STATIC);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
}

void Database::ClearAuthFailure(const std::string& ip) {
    RemoveBlacklist(ip);
    if (db_ && !ip.empty()) {
        const char* cleanSql = "DELETE FROM login_failures WHERE ip = ?;";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, cleanSql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_STATIC);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
}

std::string Database::GetConfig(const std::string& key, const std::string& defaultVal) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_) return defaultVal;
    const char* sql = "SELECT value FROM configs WHERE key = ?;";
    sqlite3_stmt* stmt = nullptr;
    std::string val = defaultVal;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* v = (const char*)sqlite3_column_text(stmt, 0);
            if (v) val = v;
        }
        sqlite3_finalize(stmt);
    }
    return val;
}

bool Database::SetConfig(const std::string& key, const std::string& value) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_) return false;
    const char* sql = "INSERT OR REPLACE INTO configs (key, value) VALUES (?, ?);";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, value.c_str(), -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

void Database::EnsureFallbackRule() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_) return;

    // 1. 获取所有 is_fallback = 1 的规则 ID
    // 排序逻辑：优先保留已启用的；其次优先保留配置了代理节点或分组的；再次优先保留 ID 最大的（用户最新配置/导入的）
    std::vector<int> fallbackIds;
    sqlite3_stmt* stmt = nullptr;
    const char* listSql = "SELECT id FROM routing_rules WHERE is_fallback = 1 "
                          "ORDER BY (CASE WHEN enabled = 1 THEN 0 ELSE 1 END) ASC, "
                          "(CASE WHEN proxy_id != 0 OR (target_group IS NOT NULL AND target_group != '') THEN 0 ELSE 1 END) ASC, "
                          "id DESC;";
    if (sqlite3_prepare_v2(db_, listSql, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            fallbackIds.push_back(sqlite3_column_int(stmt, 0));
        }
        sqlite3_finalize(stmt);
    }

    if (fallbackIds.size() > 1) {
        // 发现多条兜底规则！仅保留第一条（最优先生效的），清理删除其余所有重复的兜底规则
        for (size_t i = 1; i < fallbackIds.size(); ++i) {
            std::string delSql = "DELETE FROM routing_rules WHERE id = " + std::to_string(fallbackIds[i]) + ";";
            sqlite3_exec(db_, delSql.c_str(), nullptr, nullptr, nullptr);
        }
    } else if (fallbackIds.empty()) {
        // 如果一条兜底规则都没有，检查是否有 match_type='all' 或 match_value='*' 的旧规则可直接标记为兜底
        int existingId = 0;
        if (sqlite3_prepare_v2(db_, "SELECT id FROM routing_rules WHERE match_type = 'all' OR match_value = '*' LIMIT 1;", -1, &stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                existingId = sqlite3_column_int(stmt, 0);
            }
            sqlite3_finalize(stmt);
        }

        if (existingId > 0) {
            std::string updSql = "UPDATE routing_rules SET is_fallback = 1, match_type = 'all', match_value = '*' WHERE id = " + std::to_string(existingId) + ";";
            sqlite3_exec(db_, updSql.c_str(), nullptr, nullptr, nullptr);
        } else {
            // 获取当前普通规则最大优先级
            int maxPrio = 0;
            if (sqlite3_prepare_v2(db_, "SELECT COALESCE(MAX(priority), 0) FROM routing_rules WHERE is_fallback = 0;", -1, &stmt, nullptr) == SQLITE_OK) {
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    maxPrio = sqlite3_column_int(stmt, 0);
                }
                sqlite3_finalize(stmt);
            }
            int newPrio = (maxPrio >= 999999) ? (maxPrio + 1) : 999999;
            const char* insertSql = "INSERT INTO routing_rules (priority, match_type, match_value, proxy_id, description, enabled, is_fallback) "
                                    "VALUES (?, 'all', '*', 0, '默认兜底规则 (直连)', 1, 1);";
            if (sqlite3_prepare_v2(db_, insertSql, -1, &stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, newPrio);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        }
    }

    // 确保保留的唯一定义兜底规则 priority 位于所有普通规则之后 (>= 999999)
    int maxRegularPrio = 0;
    if (sqlite3_prepare_v2(db_, "SELECT COALESCE(MAX(priority), 0) FROM routing_rules WHERE is_fallback = 0;", -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            maxRegularPrio = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    int fallbackPrio = (maxRegularPrio >= 999999) ? (maxRegularPrio + 1) : 999999;
    std::string updPrioSql = "UPDATE routing_rules SET priority = " + std::to_string(fallbackPrio) + " WHERE is_fallback = 1;";
    sqlite3_exec(db_, updPrioSql.c_str(), nullptr, nullptr, nullptr);
}

bool Database::GetFallbackRule(RoutingRule& outRule) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_) return false;

    const char* sql = "SELECT id, priority, match_type, match_value, proxy_id, target_group, description, enabled, is_fallback, created_at "
                      "FROM routing_rules WHERE is_fallback = 1 AND enabled = 1 LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            outRule.id = sqlite3_column_int(stmt, 0);
            outRule.priority = sqlite3_column_int(stmt, 1);
            outRule.matchType = (const char*)sqlite3_column_text(stmt, 2) ? (const char*)sqlite3_column_text(stmt, 2) : "all";
            outRule.matchValue = (const char*)sqlite3_column_text(stmt, 3) ? (const char*)sqlite3_column_text(stmt, 3) : "*";
            outRule.proxyId = sqlite3_column_int(stmt, 4);
            outRule.targetGroup = (const char*)sqlite3_column_text(stmt, 5) ? (const char*)sqlite3_column_text(stmt, 5) : "";
            outRule.description = (const char*)sqlite3_column_text(stmt, 6) ? (const char*)sqlite3_column_text(stmt, 6) : "";
            outRule.enabled = sqlite3_column_int(stmt, 7) != 0;
            outRule.isFallback = sqlite3_column_int(stmt, 8) != 0;
            outRule.createdAt = (const char*)sqlite3_column_text(stmt, 9) ? (const char*)sqlite3_column_text(stmt, 9) : "";
            sqlite3_finalize(stmt);
            return true;
        }
        sqlite3_finalize(stmt);
    }
    return false;
}

bool Database::RenamePortGroup(const std::string& oldName, const std::string& newName) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_ || oldName.empty() || newName.empty()) return false;
    const char* sql = "UPDATE proxy_ports SET group_name = ? WHERE group_name = ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, newName.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, oldName.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

std::vector<DailyTrafficSummary> Database::GetPortDailyTrafficHistory(int days, int portId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<DailyTrafficSummary> summaries;
    if (!db_) return summaries;

    auto dateList = Utils::GetPastDates(days);
    for (const auto& d : dateList) {
        std::string sql;
        if (portId > 0) {
            sql = "SELECT SUM(upload_bytes), SUM(download_bytes) FROM port_traffic_records WHERE date = '" + d + "' AND port_id = " + std::to_string(portId) + ";";
        } else {
            sql = "SELECT SUM(upload_bytes), SUM(download_bytes) FROM port_traffic_records WHERE date = '" + d + "';";
        }

        sqlite3_stmt* stmt = nullptr;
        DailyTrafficSummary s;
        s.date = d;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                s.uploadBytes = sqlite3_column_int64(stmt, 0);
                s.downloadBytes = sqlite3_column_int64(stmt, 1);
                s.totalBytes = s.uploadBytes + s.downloadBytes;
            }
            sqlite3_finalize(stmt);
        }
        summaries.push_back(s);
    }
    return summaries;
}

std::vector<MonthlyTrafficSummary> Database::GetPortAnnualTrafficHistory(int year, int portId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<MonthlyTrafficSummary> summaries;
    if (!db_) return summaries;
    if (year <= 0) {
        std::string curDate = Utils::GetCurrentDate();
        year = std::atoi(curDate.substr(0, 4).c_str());
    }
    for (int m = 1; m <= 12; ++m) {
        char buf[16] = {};
        snprintf(buf, sizeof(buf), "%04d-%02d", year, m);
        std::string mStr = buf;
        std::string pattern = mStr + "%";

        std::string sql;
        if (portId > 0) {
            sql = "SELECT SUM(upload_bytes), SUM(download_bytes) FROM port_traffic_records WHERE date LIKE '" + pattern + "' AND port_id = " + std::to_string(portId) + ";";
        } else {
            sql = "SELECT SUM(upload_bytes), SUM(download_bytes) FROM port_traffic_records WHERE date LIKE '" + pattern + "';";
        }

        MonthlyTrafficSummary s;
        s.month = mStr;
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                s.uploadBytes = sqlite3_column_int64(stmt, 0);
                s.downloadBytes = sqlite3_column_int64(stmt, 1);
                s.totalBytes = s.uploadBytes + s.downloadBytes;
            }
            sqlite3_finalize(stmt);
        }
        summaries.push_back(s);
    }
    return summaries;
}

std::vector<int> Database::GetPortTrafficYears() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<int> years;
    if (!db_) return years;
    const char* sql = "SELECT DISTINCT substr(date, 1, 4) FROM port_traffic_records ORDER BY date DESC;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* y = (const char*)sqlite3_column_text(stmt, 0);
            if (y && strlen(y) == 4) {
                years.push_back(std::atoi(y));
            }
        }
        sqlite3_finalize(stmt);
    }
    if (years.empty()) {
        std::string curDate = Utils::GetCurrentDate();
        years.push_back(std::atoi(curDate.substr(0, 4).c_str()));
    }
    return years;
}

std::vector<BanInfo> Database::GetWhitelist() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<BanInfo> list;
    if (!db_) return list;
    const char* sql = "SELECT id, ip, remark, created_at FROM whitelist ORDER BY id DESC;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            BanInfo info;
            info.id = sqlite3_column_int(stmt, 0);
            const char* ip = (const char*)sqlite3_column_text(stmt, 1);
            info.ip = ip ? ip : "";
            const char* rem = (const char*)sqlite3_column_text(stmt, 2);
            info.remark = rem ? rem : "";
            const char* cat = (const char*)sqlite3_column_text(stmt, 3);
            info.createdAt = cat ? cat : "";
            list.push_back(info);
        }
        sqlite3_finalize(stmt);
    }
    return list;
}

bool Database::AddToWhitelist(const std::string& ip, const std::string& remark) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_ || ip.empty()) return false;
    const char* sql = "INSERT OR REPLACE INTO whitelist (ip, remark) VALUES (?, ?);";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, remark.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool Database::RemoveFromWhitelist(int id) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_ || id <= 0) return false;
    std::string sql = "DELETE FROM whitelist WHERE id = " + std::to_string(id) + ";";
    return sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK;
}

bool Database::RemoveFromWhitelistByIP(const std::string& ip) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_ || ip.empty()) return false;
    const char* sql = "DELETE FROM whitelist WHERE ip = ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool Database::IsWhitelisted(const std::string& ip) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_ || ip.empty()) return false;
    const char* sql = "SELECT id FROM whitelist WHERE ip = ?;";
    sqlite3_stmt* stmt = nullptr;
    bool found = false;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) found = true;
        sqlite3_finalize(stmt);
    }
    return found;
}

std::vector<BanInfo> Database::GetNoAuthList() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<BanInfo> list;
    if (!db_) return list;
    const char* sql = "SELECT id, ip, remark, created_at FROM no_auth ORDER BY id DESC;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            BanInfo info;
            info.id = sqlite3_column_int(stmt, 0);
            const char* ip = (const char*)sqlite3_column_text(stmt, 1);
            info.ip = ip ? ip : "";
            const char* rem = (const char*)sqlite3_column_text(stmt, 2);
            info.remark = rem ? rem : "";
            const char* cat = (const char*)sqlite3_column_text(stmt, 3);
            info.createdAt = cat ? cat : "";
            list.push_back(info);
        }
        sqlite3_finalize(stmt);
    }
    return list;
}

bool Database::AddToNoAuthList(const std::string& ip, const std::string& remark) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_ || ip.empty()) return false;
    const char* sql = "INSERT OR REPLACE INTO no_auth (ip, remark) VALUES (?, ?);";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, remark.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool Database::RemoveFromNoAuthList(int id) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_ || id <= 0) return false;
    std::string sql = "DELETE FROM no_auth WHERE id = " + std::to_string(id) + ";";
    return sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK;
}

bool Database::RemoveFromNoAuthListByIP(const std::string& ip) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_ || ip.empty()) return false;
    const char* sql = "DELETE FROM no_auth WHERE ip = ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool Database::IsNoAuthIP(const std::string& ip) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_ || ip.empty()) return false;
    const char* sql = "SELECT id FROM no_auth WHERE ip = ?;";
    sqlite3_stmt* stmt = nullptr;
    bool found = false;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) found = true;
        sqlite3_finalize(stmt);
    }
    return found;
}

nlohmann::json Database::ExportConfig() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    nlohmann::json root;
    root["format"] = "ProxyRelayConfig";
    root["version"] = "1.0";
    root["platform"] = "openwrt";
    root["export_time"] = Utils::GetCurrentDateTime();

    // 1. 用户列表
    nlohmann::json usersArr = nlohmann::json::array();
    for (const auto& u : GetAllUsers()) {
        nlohmann::json item;
        item["id"] = u.id;
        item["username"] = u.username;
        item["password"] = u.password;
        item["allowedIPs"] = u.allowedIPs;
        item["dailyLimit"] = u.dailyLimit;
        item["monthlyLimit"] = u.monthlyLimit;
        item["enabled"] = u.enabled;
        item["remark"] = u.remark;
        item["expiryDate"] = u.expiryDate;
        item["allowedTargets"] = u.allowedTargets;
        item["priority"] = u.priority;
        usersArr.push_back(item);
    }
    root["users"] = usersArr;

    // 2. 代理节点列表
    nlohmann::json portsArr = nlohmann::json::array();
    for (const auto& p : GetAllProxyPorts()) {
        nlohmann::json item;
        item["id"] = p.id;
        item["listenPort"] = p.listenPort;
        item["upstreamType"] = p.upstreamType;
        item["upstreamHost"] = p.upstreamHost;
        item["upstreamPort"] = p.upstreamPort;
        item["upstreamUser"] = p.upstreamUser;
        item["upstreamPass"] = p.upstreamPass;
        item["enabled"] = p.enabled;
        item["autoCheck"] = p.autoCheck;
        item["description"] = p.description;
        item["priority"] = p.priority;
        item["groupName"] = p.groupName;
        item["xrayConfig"] = p.xrayConfig;
        item["clashConfig"] = p.clashConfig;
        item["clashSubscriptionId"] = p.clashSubscriptionId;
        item["clashNodeName"] = p.clashNodeName;
        item["allowedTargets"] = p.allowedTargets;
        portsArr.push_back(item);
    }
    root["proxy_ports"] = portsArr;

    // 3. Clash 订阅列表
    nlohmann::json subsArr = nlohmann::json::array();
    for (const auto& s : GetAllSubscriptions()) {
        nlohmann::json item;
        item["id"] = s.id;
        item["name"] = s.name;
        item["url"] = s.url;
        item["updateIntervalDays"] = s.updateIntervalDays;
        item["updateTime"] = s.updateTime;
        item["websiteUrl"] = s.websiteUrl;
        item["includeFilter"] = s.includeFilter;
        item["excludeFilter"] = s.excludeFilter;
        item["resetCycleDays"] = s.resetCycleDays;
        item["resetStartDate"] = s.resetStartDate;
        subsArr.push_back(item);
    }
    root["clash_subscriptions"] = subsArr;

    // 4. 路由分流规则
    nlohmann::json rulesArr = nlohmann::json::array();
    for (const auto& r : GetAllRoutingRules()) {
        nlohmann::json item;
        item["id"] = r.id;
        item["priority"] = r.priority;
        item["matchType"] = r.matchType;
        item["matchValue"] = r.matchValue;
        item["proxyId"] = r.proxyId;
        item["targetGroup"] = r.targetGroup;
        item["enabled"] = r.enabled;
        item["description"] = r.description;
        item["isFallback"] = r.isFallback;
        rulesArr.push_back(item);
    }
    root["routing_rules"] = rulesArr;

    // 5. 安全列表 (白名单、黑名单、免认证)
    nlohmann::json whiteArr = nlohmann::json::array();
    for (const auto& w : GetWhitelist()) {
        whiteArr.push_back({ {"ip", w.ip}, {"remark", w.remark} });
    }
    root["ip_whitelist"] = whiteArr;

    nlohmann::json blackArr = nlohmann::json::array();
    for (const auto& b : GetBlacklist()) {
        blackArr.push_back({ {"ip", b.ip}, {"remark", b.reason} });
    }
    root["ip_blacklist"] = blackArr;

    nlohmann::json noAuthArr = nlohmann::json::array();
    for (const auto& n : GetNoAuthList()) {
        noAuthArr.push_back({ {"ip", n.ip}, {"remark", n.remark} });
    }
    root["ip_no_auth"] = noAuthArr;

    // 6. 系统配置项
    nlohmann::json cfgObj = nlohmann::json::object();
    static const std::vector<std::string> cfgKeys = {
        "inbound_proxy_type", "auto_proxy_port", "relay_buffer_size_kb",
        "health_check_targets", "log_retention_days", "enable_audit_log",
        "china_direct_enabled", "china_direct_cn_domains", "china_direct_popular_sites",
        "china_direct_ips", "china_direct_lan", "china_direct_custom",
        "china_ip_sub_url", "china_ip_sub_interval_days"
    };
    for (const auto& k : cfgKeys) {
        std::string val = GetConfig(k, "");
        if (!val.empty()) {
            cfgObj[k] = val;
        }
    }
    root["system_config"] = cfgObj;

    return root;
}

bool Database::ImportConfig(const nlohmann::json& root, bool overwrite, std::string& errorMsg) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!root.is_object()) {
        errorMsg = "配置文件必须是有效的 JSON 对象";
        return false;
    }

    sqlite3_exec(db_, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);

    try {
        if (overwrite) {
            sqlite3_exec(db_, "DELETE FROM routing_rules;", nullptr, nullptr, nullptr);
            sqlite3_exec(db_, "DELETE FROM proxy_ports;", nullptr, nullptr, nullptr);
            sqlite3_exec(db_, "DELETE FROM subscriptions;", nullptr, nullptr, nullptr);
            sqlite3_exec(db_, "DELETE FROM users;", nullptr, nullptr, nullptr);
            sqlite3_exec(db_, "DELETE FROM blacklist;", nullptr, nullptr, nullptr);
            sqlite3_exec(db_, "DELETE FROM whitelist;", nullptr, nullptr, nullptr);
            sqlite3_exec(db_, "DELETE FROM no_auth;", nullptr, nullptr, nullptr);
        }

        // 1. Clash 订阅
        std::map<int, int> oldSubIdToNewSubId;
        if (root.contains("clash_subscriptions") && root["clash_subscriptions"].is_array()) {
            for (const auto& sJson : root["clash_subscriptions"]) {
                ClashSubscription s;
                int oldId = sJson.value("id", 0);
                s.name = sJson.value("name", "");
                s.url = sJson.value("url", "");
                s.updateIntervalDays = sJson.value("updateIntervalDays", 0);
                s.updateTime = sJson.value("updateTime", "04:00");
                s.websiteUrl = sJson.value("websiteUrl", "");
                s.includeFilter = sJson.value("includeFilter", "");
                s.excludeFilter = sJson.value("excludeFilter", "");
                s.resetCycleDays = sJson.value("resetCycleDays", 0);
                s.resetStartDate = sJson.value("resetStartDate", "");

                bool exists = false;
                if (!overwrite) {
                    for (const auto& existing : GetAllSubscriptions()) {
                        if (existing.name == s.name || existing.url == s.url) {
                            s.id = existing.id;
                            SaveSubscription(s);
                            oldSubIdToNewSubId[oldId] = existing.id;
                            exists = true;
                            break;
                        }
                    }
                }
                if (!exists) {
                    s.id = 0;
                    SaveSubscription(s);
                    oldSubIdToNewSubId[oldId] = s.id;
                }
            }
        }

        // 2. 用户列表
        if (root.contains("users") && root["users"].is_array()) {
            for (const auto& uJson : root["users"]) {
                UserInfo u;
                u.username = uJson.value("username", "");
                if (u.username.empty()) continue;
                u.password = uJson.value("password", "");
                u.allowedIPs = uJson.value("allowedIPs", "*");
                u.dailyLimit = uJson.value("dailyLimit", (int64_t)0);
                u.monthlyLimit = uJson.value("monthlyLimit", (int64_t)0);
                u.enabled = uJson.value("enabled", true);
                u.remark = uJson.value("remark", "");
                u.expiryDate = uJson.value("expiryDate", "");
                u.allowedTargets = uJson.value("allowedTargets", "*");
                u.priority = uJson.value("priority", 0);

                UserInfo existing;
                if (GetUserByUsername(u.username, existing)) {
                    u.id = existing.id;
                } else {
                    u.id = 0;
                }
                SaveUser(u);
            }
        }

        // 3. 代理节点列表
        std::map<int, int> oldPortIdToNewPortId;
        if (root.contains("proxy_ports") && root["proxy_ports"].is_array()) {
            for (const auto& pJson : root["proxy_ports"]) {
                ProxyPort p;
                int oldPortId = pJson.value("id", 0);
                p.listenPort = pJson.value("listenPort", 0);
                p.upstreamType = pJson.value("upstreamType", "http");
                p.upstreamHost = pJson.value("upstreamHost", "");
                p.upstreamPort = pJson.value("upstreamPort", 0);
                p.upstreamUser = pJson.value("upstreamUser", "");
                p.upstreamPass = pJson.value("upstreamPass", "");
                p.enabled = pJson.value("enabled", true);
                p.autoCheck = pJson.value("autoCheck", true);
                p.description = pJson.value("description", "");
                p.priority = pJson.value("priority", 0);
                p.groupName = pJson.value("groupName", "默认");
                p.xrayConfig = pJson.value("xrayConfig", "");
                p.clashConfig = pJson.value("clashConfig", "");
                int oldSubId = pJson.value("clashSubscriptionId", 0);
                if (oldSubIdToNewSubId.count(oldSubId)) {
                    p.clashSubscriptionId = oldSubIdToNewSubId[oldSubId];
                } else {
                    p.clashSubscriptionId = oldSubId;
                }
                p.clashNodeName = pJson.value("clashNodeName", "");
                p.allowedTargets = pJson.value("allowedTargets", "*");

                p.id = 0;
                if (SaveProxyPort(p)) {
                    int newPortId = (int)sqlite3_last_insert_rowid(db_);
                    if (oldPortId > 0) {
                        oldPortIdToNewPortId[oldPortId] = newPortId;
                    }
                }
            }
        }

        // 4. 路由分流规则
        if (root.contains("routing_rules") && root["routing_rules"].is_array()) {
            for (const auto& rJson : root["routing_rules"]) {
                RoutingRule r;
                r.priority = rJson.value("priority", 0);
                r.matchType = rJson.value("matchType", "domain");
                r.matchValue = rJson.value("matchValue", "");
                int oldProxyId = rJson.value("proxyId", 0);
                if (oldProxyId > 0 && oldPortIdToNewPortId.count(oldProxyId)) {
                    r.proxyId = oldPortIdToNewPortId[oldProxyId];
                } else {
                    r.proxyId = oldProxyId;
                }
                r.targetGroup = rJson.value("targetGroup", "");
                r.enabled = rJson.value("enabled", true);
                r.description = rJson.value("description", "");
                bool isFallback = rJson.value("isFallback", false) || (r.matchType == "all" && r.matchValue == "*");
                r.isFallback = isFallback;

                if (isFallback) {
                    // 全局系统只能保留一条兜底规则：检查当前库中是否已有兜底规则
                    int existingFallbackId = 0;
                    sqlite3_stmt* stmtFb = nullptr;
                    if (sqlite3_prepare_v2(db_, "SELECT id FROM routing_rules WHERE is_fallback = 1 LIMIT 1;", -1, &stmtFb, nullptr) == SQLITE_OK) {
                        if (sqlite3_step(stmtFb) == SQLITE_ROW) {
                            existingFallbackId = sqlite3_column_int(stmtFb, 0);
                        }
                        sqlite3_finalize(stmtFb);
                    }
                    if (existingFallbackId > 0) {
                        // 覆盖更新已有的兜底规则，绝不插入第二条兜底规则
                        r.id = existingFallbackId;
                        SaveRoutingRule(r);
                        continue;
                    }
                } else if (!overwrite) {
                    // 增量合并模式下普通规则：若已存在相同匹配表达式与类型的规则，更新该规则
                    int existingRuleId = 0;
                    sqlite3_stmt* stmtRule = nullptr;
                    if (sqlite3_prepare_v2(db_, "SELECT id FROM routing_rules WHERE is_fallback = 0 AND match_type = ? AND match_value = ? LIMIT 1;", -1, &stmtRule, nullptr) == SQLITE_OK) {
                        sqlite3_bind_text(stmtRule, 1, r.matchType.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_bind_text(stmtRule, 2, r.matchValue.c_str(), -1, SQLITE_TRANSIENT);
                        if (sqlite3_step(stmtRule) == SQLITE_ROW) {
                            existingRuleId = sqlite3_column_int(stmtRule, 0);
                        }
                        sqlite3_finalize(stmtRule);
                    }
                    if (existingRuleId > 0) {
                        r.id = existingRuleId;
                        SaveRoutingRule(r);
                        continue;
                    }
                }

                r.id = 0;
                SaveRoutingRule(r);
            }
        }

        // 5. 安全列表
        if (root.contains("ip_whitelist") && root["ip_whitelist"].is_array()) {
            for (const auto& w : root["ip_whitelist"]) {
                std::string ip = w.value("ip", "");
                std::string remark = w.value("remark", "");
                if (!ip.empty()) AddToWhitelist(ip, remark);
            }
        }
        if (root.contains("ip_blacklist") && root["ip_blacklist"].is_array()) {
            for (const auto& b : root["ip_blacklist"]) {
                std::string ip = b.value("ip", "");
                std::string remark = b.value("remark", "");
                if (!ip.empty()) AddBlacklist(ip, remark);
            }
        }
        if (root.contains("ip_no_auth") && root["ip_no_auth"].is_array()) {
            for (const auto& n : root["ip_no_auth"]) {
                std::string ip = n.value("ip", "");
                std::string remark = n.value("remark", "");
                if (!ip.empty()) AddToNoAuthList(ip, remark);
            }
        }

        // 6. 系统配置项
        if (root.contains("system_config") && root["system_config"].is_object()) {
            for (auto it = root["system_config"].begin(); it != root["system_config"].end(); ++it) {
                if (it.value().is_string()) {
                    SetConfig(it.key(), it.value().get<std::string>());
                } else if (it.value().is_number()) {
                    SetConfig(it.key(), std::to_string(it.value().get<int64_t>()));
                } else if (it.value().is_boolean()) {
                    SetConfig(it.key(), it.value().get<bool>() ? "1" : "0");
                }
            }
        }

        EnsureFallbackRule();
        DeduplicateProxyPorts();

        sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, nullptr);
        return true;
    } catch (const std::exception& e) {
        sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
        errorMsg = std::string("导入异常: ") + e.what();
        return false;
    }
}
