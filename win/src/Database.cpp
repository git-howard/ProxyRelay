#include "Database.h"
#include "Utils.h"
#include "TrafficMonitor.h"
#include "ClashManager.h"
#include <sstream>
#include <set>
#include <iomanip>
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
    
    dbPath_ = dbPath;
    
    int rc = sqlite3_open(dbPath.c_str(), &db_);
    if (rc != SQLITE_OK) {
        Utils::LogError("Failed to open database: " + std::string(sqlite3_errmsg(db_)));
        return false;
    }
    
    // 设置繁忙等待超时 5000ms，保障控制台与后台系统服务并发读写不锁表
    sqlite3_busy_timeout(db_, 5000);
    
    // 启用WAL模式提高性能
    ExecuteSQL("PRAGMA journal_mode=WAL;");
    ExecuteSQL("PRAGMA synchronous=NORMAL;");
    
    bool ok = CreateTables();
    if (ok) {
        EnsureFallbackRule();
        RepairClashPorts();
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

int Database::GetDataVersion() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_) return 0;
    sqlite3_stmt* stmt = nullptr;
    int version = 0;
    if (sqlite3_prepare_v2(db_, "PRAGMA data_version;", -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            version = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    return version;
}

bool Database::CreateTables() {
    // 用户表
    const char* usersTable = R"(
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            allowed_ips TEXT DEFAULT '*',
            daily_limit INTEGER DEFAULT 0,
            monthly_limit INTEGER DEFAULT 0,
            enabled INTEGER DEFAULT 1,
            remark TEXT DEFAULT '',
            expiry_date TEXT DEFAULT '',
            allowed_targets TEXT DEFAULT '*',
            priority INTEGER DEFAULT 0,
            quota_reset_month TEXT DEFAULT '',
            quota_offset_bytes INTEGER DEFAULT 0,
            quota_reset_date TEXT DEFAULT '',
            daily_quota_offset_bytes INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    )";
    
    // 代理端口表 - listen_port 可以为 NULL（表示不启用本地监听）
    const char* proxyPortsTable = R"(
        CREATE TABLE IF NOT EXISTS proxy_ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            listen_port INTEGER DEFAULT NULL,
            upstream_type TEXT NOT NULL,
            upstream_host TEXT NOT NULL,
            upstream_port INTEGER NOT NULL,
            upstream_user TEXT DEFAULT '',
            upstream_pass TEXT DEFAULT '',
            enabled INTEGER DEFAULT 1,
            description TEXT DEFAULT '',
            priority INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    )";
    
    // 流量记录表
    const char* trafficTable = R"(
        CREATE TABLE IF NOT EXISTS traffic_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            date TEXT NOT NULL,
            upload_bytes INTEGER DEFAULT 0,
            download_bytes INTEGER DEFAULT 0,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, date),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    )";
    
    // 创建索引
    const char* trafficIndex = R"(
        CREATE INDEX IF NOT EXISTS idx_traffic_user_date ON traffic_records(user_id, date);
    )";
    
    // 系统配置表
    const char* configTable = R"(
        CREATE TABLE IF NOT EXISTS system_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    )";
    
    // 路由规则表
    const char* routingRulesTable = R"(
        CREATE TABLE IF NOT EXISTS routing_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            priority INTEGER DEFAULT 0,
            match_type TEXT NOT NULL,
            match_value TEXT NOT NULL,
            proxy_id INTEGER DEFAULT 0,
            enabled INTEGER DEFAULT 1,
            description TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            is_fallback INTEGER DEFAULT 0
        );
    )";
    
    // 端口流量统计表
    const char* portTrafficStatsTable = R"(
        CREATE TABLE IF NOT EXISTS port_traffic_stats (
            port_id INTEGER PRIMARY KEY,
            upload_1h INTEGER DEFAULT 0,
            download_1h INTEGER DEFAULT 0,
            upload_24h INTEGER DEFAULT 0,
            download_24h INTEGER DEFAULT 0,
            upload_week INTEGER DEFAULT 0,
            download_week INTEGER DEFAULT 0,
            upload_month INTEGER DEFAULT 0,
            download_month INTEGER DEFAULT 0,
            upload_last_month INTEGER DEFAULT 0,
            download_last_month INTEGER DEFAULT 0,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    )";
    
    // 用户流量统计表
    const char* userTrafficStatsTable = R"(
        CREATE TABLE IF NOT EXISTS user_traffic_stats (
            user_id INTEGER PRIMARY KEY,
            upload_1h INTEGER DEFAULT 0,
            download_1h INTEGER DEFAULT 0,
            upload_24h INTEGER DEFAULT 0,
            download_24h INTEGER DEFAULT 0,
            upload_week INTEGER DEFAULT 0,
            download_week INTEGER DEFAULT 0,
            upload_month INTEGER DEFAULT 0,
            download_month INTEGER DEFAULT 0,
            upload_last_month INTEGER DEFAULT 0,
            download_last_month INTEGER DEFAULT 0,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    )";
    
    // 白名单表
    const char* whitelistTable = R"(
        CREATE TABLE IF NOT EXISTS ip_whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE,
            remark TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    )";

    // 黑名单表
    const char* blacklistTable = R"(
        CREATE TABLE IF NOT EXISTS ip_blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE,
            remark TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    )";

    // 自动封禁表
    const char* autoBanTable = R"(
        CREATE TABLE IF NOT EXISTS auto_ban_list (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE,
            expiry_time INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    )";

    // 登录失败记录表
    const char* loginFailTable = R"(
        CREATE TABLE IF NOT EXISTS login_failures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            fail_time INTEGER DEFAULT (strftime('%s', 'now'))
        );
    )";
    const char* loginFailIndex = "CREATE INDEX IF NOT EXISTS idx_login_failures_ip_time ON login_failures(ip, fail_time);";
    
    // 免认证IP表
    const char* noAuthTable = R"(
        CREATE TABLE IF NOT EXISTS ip_no_auth (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE,
            remark TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    )";
    
    if (!ExecuteSQL(usersTable)) return false;
    if (!ExecuteSQL(proxyPortsTable)) return false;
    if (!ExecuteSQL(trafficTable)) return false;
    if (!ExecuteSQL(trafficIndex)) return false;
    if (!ExecuteSQL(configTable)) return false;
    if (!ExecuteSQL(routingRulesTable)) return false;
    if (!ExecuteSQL(portTrafficStatsTable)) return false;
    if (!ExecuteSQL(userTrafficStatsTable)) return false;
    if (!ExecuteSQL(whitelistTable)) return false;
    if (!ExecuteSQL(blacklistTable)) return false;
    if (!ExecuteSQL(autoBanTable)) return false;
    if (!ExecuteSQL(loginFailTable)) return false;
    if (!ExecuteSQL(loginFailIndex)) return false;
    if (!ExecuteSQL(noAuthTable)) return false;
    
    // 端口日流量明细表（与用户日流量保持一致性）
    const char* portTrafficRecordsTable = R"(
        CREATE TABLE IF NOT EXISTS port_traffic_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            port_id INTEGER NOT NULL,
            date TEXT NOT NULL,
            upload_bytes INTEGER DEFAULT 0,
            download_bytes INTEGER DEFAULT 0,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(port_id, date),
            FOREIGN KEY (port_id) REFERENCES proxy_ports(id) ON DELETE CASCADE
        );
    )";
    ExecuteSQL(portTrafficRecordsTable);
    ExecuteSQL("CREATE INDEX IF NOT EXISTS idx_traffic_port_date ON port_traffic_records(port_id, date);");
    
    // Schema Migration: 检查是否需要添加 priority 列
    sqlite3_stmt* checkStmt;
    if (sqlite3_prepare_v2(db_, "SELECT priority FROM proxy_ports LIMIT 1", -1, &checkStmt, nullptr) != SQLITE_OK) {
        ExecuteSQL("ALTER TABLE proxy_ports ADD COLUMN priority INTEGER DEFAULT 0;");
        ExecuteSQL("UPDATE proxy_ports SET priority = id;");
    } else {
        sqlite3_finalize(checkStmt);
    }
    
    // Schema Migration: 添加上月流量列
    if (sqlite3_prepare_v2(db_, "SELECT upload_last_month FROM port_traffic_stats LIMIT 1", -1, &checkStmt, nullptr) != SQLITE_OK) {
        ExecuteSQL("ALTER TABLE port_traffic_stats ADD COLUMN upload_last_month INTEGER DEFAULT 0;");
        ExecuteSQL("ALTER TABLE port_traffic_stats ADD COLUMN download_last_month INTEGER DEFAULT 0;");
    } else {
        sqlite3_finalize(checkStmt);
    }
    if (sqlite3_prepare_v2(db_, "SELECT upload_last_month FROM user_traffic_stats LIMIT 1", -1, &checkStmt, nullptr) != SQLITE_OK) {
        ExecuteSQL("ALTER TABLE user_traffic_stats ADD COLUMN upload_last_month INTEGER DEFAULT 0;");
        ExecuteSQL("ALTER TABLE user_traffic_stats ADD COLUMN download_last_month INTEGER DEFAULT 0;");
    } else {
        sqlite3_finalize(checkStmt);
    }
    
    // Schema Migration: 用户表添加账户到期日期
    if (sqlite3_prepare_v2(db_, "SELECT expiry_date FROM users LIMIT 1", -1, &checkStmt, nullptr) != SQLITE_OK) {
        ExecuteSQL("ALTER TABLE users ADD COLUMN expiry_date TEXT DEFAULT '';");
    } else {
        sqlite3_finalize(checkStmt);
    }
    
    // Schema Migration: 用户表添加 priority 列
    if (sqlite3_prepare_v2(db_, "SELECT priority FROM users LIMIT 1", -1, &checkStmt, nullptr) != SQLITE_OK) {
        ExecuteSQL("ALTER TABLE users ADD COLUMN priority INTEGER DEFAULT 0;");
        ExecuteSQL("UPDATE users SET priority = id;");
    } else {
        sqlite3_finalize(checkStmt);
    }
    
    // Schema Migration: 移除 listen_port 的 UNIQUE 约束（允许多个配置使用相同端口或为0/NULL）
    // 检查是否存在 UNIQUE 约束：尝试插入两个相同的 listen_port，如果失败说明有约束
    // 更简单的方法：检查表结构中是否有 UNIQUE 约束，通过重建表来移除
    // SQLite 不支持 ALTER COLUMN，所以需要重建表
    {
        // 检查是否需要迁移（通过检查 config 表中的标志）
        std::string migrationDone = GetConfig("migration_listen_port_nullable", "0");
        if (migrationDone == "0") {
            // 执行迁移：重建 proxy_ports 表
            const char* migrationSql = R"(
                -- 创建临时表
                CREATE TABLE IF NOT EXISTS proxy_ports_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    listen_port INTEGER DEFAULT NULL,
                    upstream_type TEXT NOT NULL,
                    upstream_host TEXT NOT NULL,
                    upstream_port INTEGER NOT NULL,
                    upstream_user TEXT DEFAULT '',
                    upstream_pass TEXT DEFAULT '',
                    enabled INTEGER DEFAULT 1,
                    description TEXT DEFAULT '',
                    priority INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
                -- 复制数据（将 0 转换为 NULL）
                INSERT INTO proxy_ports_new (id, listen_port, upstream_type, upstream_host, upstream_port, 
                                             upstream_user, upstream_pass, enabled, description, priority, created_at)
                SELECT id, CASE WHEN listen_port = 0 THEN NULL ELSE listen_port END, upstream_type, upstream_host, upstream_port,
                       upstream_user, upstream_pass, enabled, description, priority, created_at
                FROM proxy_ports;
                -- 删除旧表
                DROP TABLE proxy_ports;
                -- 重命名新表
                ALTER TABLE proxy_ports_new RENAME TO proxy_ports;
            )";
            
            // 分步执行
            ExecuteSQL("CREATE TABLE IF NOT EXISTS proxy_ports_new (id INTEGER PRIMARY KEY AUTOINCREMENT, listen_port INTEGER DEFAULT NULL, upstream_type TEXT NOT NULL, upstream_host TEXT NOT NULL, upstream_port INTEGER NOT NULL, upstream_user TEXT DEFAULT '', upstream_pass TEXT DEFAULT '', enabled INTEGER DEFAULT 1, description TEXT DEFAULT '', priority INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP);");
            ExecuteSQL("INSERT INTO proxy_ports_new (id, listen_port, upstream_type, upstream_host, upstream_port, upstream_user, upstream_pass, enabled, description, priority, created_at) SELECT id, CASE WHEN listen_port = 0 THEN NULL ELSE listen_port END, upstream_type, upstream_host, upstream_port, upstream_user, upstream_pass, enabled, description, priority, created_at FROM proxy_ports;");
            ExecuteSQL("DROP TABLE proxy_ports;");
            ExecuteSQL("ALTER TABLE proxy_ports_new RENAME TO proxy_ports;");
            
            // 标记迁移完成
            SetConfig("migration_listen_port_nullable", "1");
        }
    }
    
    // Schema Migration: 添加用户备注字段
    if (sqlite3_prepare_v2(db_, "SELECT remark FROM users LIMIT 1", -1, &checkStmt, nullptr) != SQLITE_OK) {
        ExecuteSQL("ALTER TABLE users ADD COLUMN remark TEXT DEFAULT '';");
    } else {
        sqlite3_finalize(checkStmt);
    }
    
    // Schema Migration: 添加 xray_config 列到 proxy_ports 表
    if (sqlite3_prepare_v2(db_, "SELECT xray_config FROM proxy_ports LIMIT 1", -1, &checkStmt, nullptr) != SQLITE_OK) {
        ExecuteSQL("ALTER TABLE proxy_ports ADD COLUMN xray_config TEXT DEFAULT '';");
    } else {
        sqlite3_finalize(checkStmt);
    }
    
    // Schema Migration: 添加 clash_config 列到 proxy_ports 表
    if (sqlite3_prepare_v2(db_, "SELECT clash_config FROM proxy_ports LIMIT 1", -1, &checkStmt, nullptr) != SQLITE_OK) {
        ExecuteSQL("ALTER TABLE proxy_ports ADD COLUMN clash_config TEXT DEFAULT '';");
    } else {
        sqlite3_finalize(checkStmt);
    }
    
    // Schema Migration: 添加 clash_subscription_id 列到 proxy_ports 表
    if (sqlite3_prepare_v2(db_, "SELECT clash_subscription_id FROM proxy_ports LIMIT 1", -1, &checkStmt, nullptr) != SQLITE_OK) {
        ExecuteSQL("ALTER TABLE proxy_ports ADD COLUMN clash_subscription_id INTEGER DEFAULT 0;");
    } else {
        sqlite3_finalize(checkStmt);
    }
    
    // Schema Migration: 添加 clash_node_name 列到 proxy_ports 表
    if (sqlite3_prepare_v2(db_, "SELECT clash_node_name FROM proxy_ports LIMIT 1", -1, &checkStmt, nullptr) != SQLITE_OK) {
        ExecuteSQL("ALTER TABLE proxy_ports ADD COLUMN clash_node_name TEXT DEFAULT '';");
    } else {
        sqlite3_finalize(checkStmt);
    }
    
    // Schema Migration: 用户表添加配额重置偏移量字段 (用于重置额度时不清除总累计用量和历史流量)
    if (sqlite3_prepare_v2(db_, "SELECT quota_reset_month FROM users LIMIT 1", -1, &checkStmt, nullptr) != SQLITE_OK) {
        ExecuteSQL("ALTER TABLE users ADD COLUMN quota_reset_month TEXT DEFAULT '';");
        ExecuteSQL("ALTER TABLE users ADD COLUMN quota_offset_bytes INTEGER DEFAULT 0;");
        ExecuteSQL("ALTER TABLE users ADD COLUMN quota_reset_date TEXT DEFAULT '';");
        ExecuteSQL("ALTER TABLE users ADD COLUMN daily_quota_offset_bytes INTEGER DEFAULT 0;");
    } else {
        sqlite3_finalize(checkStmt);
    }
    
    // 创建 Clash 订阅表
    const char* clashSubsTable = R"(
        CREATE TABLE IF NOT EXISTS clash_subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT DEFAULT '',
            url TEXT NOT NULL,
            raw_content TEXT DEFAULT '',
            update_interval_days INTEGER DEFAULT 0,
            update_time TEXT DEFAULT '04:00',
            last_updated TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            upload_bytes INTEGER DEFAULT 0,
            download_bytes INTEGER DEFAULT 0,
            total_bytes INTEGER DEFAULT 0,
            expire_time TEXT DEFAULT '',
            website_url TEXT DEFAULT '',
            include_filter TEXT DEFAULT '',
            exclude_filter TEXT DEFAULT '',
            reset_cycle_days INTEGER DEFAULT 30,
            reset_start_date TEXT DEFAULT '',
            cycle_offset_bytes INTEGER DEFAULT 0,
            last_reset_cycle INTEGER DEFAULT 0
        );
    )";
    ExecuteSQL(clashSubsTable);

    // Schema Migration: clash_subscriptions 添加流量与有效期列
    if (sqlite3_prepare_v2(db_, "SELECT upload_bytes FROM clash_subscriptions LIMIT 1", -1, &checkStmt, nullptr) != SQLITE_OK) {
        ExecuteSQL("ALTER TABLE clash_subscriptions ADD COLUMN upload_bytes INTEGER DEFAULT 0;");
        ExecuteSQL("ALTER TABLE clash_subscriptions ADD COLUMN download_bytes INTEGER DEFAULT 0;");
        ExecuteSQL("ALTER TABLE clash_subscriptions ADD COLUMN total_bytes INTEGER DEFAULT 0;");
        ExecuteSQL("ALTER TABLE clash_subscriptions ADD COLUMN expire_time TEXT DEFAULT '';");
        ExecuteSQL("ALTER TABLE clash_subscriptions ADD COLUMN website_url TEXT DEFAULT '';");
    } else {
        sqlite3_finalize(checkStmt);
    }

    // Schema Migration: clash_subscriptions 添加 include_filter 与 exclude_filter 列
    if (sqlite3_prepare_v2(db_, "SELECT include_filter FROM clash_subscriptions LIMIT 1", -1, &checkStmt, nullptr) != SQLITE_OK) {
        ExecuteSQL("ALTER TABLE clash_subscriptions ADD COLUMN include_filter TEXT DEFAULT '';");
        ExecuteSQL("ALTER TABLE clash_subscriptions ADD COLUMN exclude_filter TEXT DEFAULT '';");
    } else {
        sqlite3_finalize(checkStmt);
    }

    // Schema Migration: clash_subscriptions 添加流量重置周期与起始日期列
    if (sqlite3_prepare_v2(db_, "SELECT reset_cycle_days FROM clash_subscriptions LIMIT 1", -1, &checkStmt, nullptr) != SQLITE_OK) {
        ExecuteSQL("ALTER TABLE clash_subscriptions ADD COLUMN reset_cycle_days INTEGER DEFAULT 30;");
        ExecuteSQL("ALTER TABLE clash_subscriptions ADD COLUMN reset_start_date TEXT DEFAULT '';");
        ExecuteSQL("ALTER TABLE clash_subscriptions ADD COLUMN cycle_offset_bytes INTEGER DEFAULT 0;");
        ExecuteSQL("ALTER TABLE clash_subscriptions ADD COLUMN last_reset_cycle INTEGER DEFAULT 0;");
    } else {
        sqlite3_finalize(checkStmt);
    }
    
    // 应用代理规则表（全局代理按进程名路由）
    const char* appProxyRulesTable = R"(
        CREATE TABLE IF NOT EXISTS app_proxy_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_name TEXT NOT NULL,
            proxy_id INTEGER NOT NULL DEFAULT -1,
            priority INTEGER DEFAULT 0,
            enabled INTEGER DEFAULT 1,
            description TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
    )";
    ExecuteSQL(appProxyRulesTable);
    
    // Schema Migration: 用户表添加 allowed_targets 列
    if (sqlite3_prepare_v2(db_, "SELECT allowed_targets FROM users LIMIT 1", -1, &checkStmt, nullptr) != SQLITE_OK) {
        ExecuteSQL("ALTER TABLE users ADD COLUMN allowed_targets TEXT DEFAULT '*';");
    } else {
        sqlite3_finalize(checkStmt);
    }
    
    // Schema Migration: 添加 auto_check 列到 proxy_ports 表
    if (sqlite3_prepare_v2(db_, "SELECT auto_check FROM proxy_ports LIMIT 1", -1, &checkStmt, nullptr) != SQLITE_OK) {
        ExecuteSQL("ALTER TABLE proxy_ports ADD COLUMN auto_check INTEGER DEFAULT 1;");
    } else {
        sqlite3_finalize(checkStmt);
    }
    
    // Schema Migration: 添加 allowed_targets 列到 proxy_ports 表
    if (sqlite3_prepare_v2(db_, "SELECT allowed_targets FROM proxy_ports LIMIT 1", -1, &checkStmt, nullptr) != SQLITE_OK) {
        ExecuteSQL("ALTER TABLE proxy_ports ADD COLUMN allowed_targets TEXT DEFAULT '*';");
    } else {
        sqlite3_finalize(checkStmt);
    }

    // Schema Migration: 添加 group_name 列到 proxy_ports 表
    if (sqlite3_prepare_v2(db_, "SELECT group_name FROM proxy_ports LIMIT 1", -1, &checkStmt, nullptr) != SQLITE_OK) {
        ExecuteSQL("ALTER TABLE proxy_ports ADD COLUMN group_name TEXT DEFAULT '';");
    } else {
        sqlite3_finalize(checkStmt);
    }

    // Schema Migration: 添加 target_group 列到 routing_rules 表
    if (sqlite3_prepare_v2(db_, "SELECT target_group FROM routing_rules LIMIT 1", -1, &checkStmt, nullptr) != SQLITE_OK) {
        ExecuteSQL("ALTER TABLE routing_rules ADD COLUMN target_group TEXT DEFAULT '';");
    } else {
        sqlite3_finalize(checkStmt);
    }

    // Schema Migration: 添加 is_fallback 列到 routing_rules 表
    if (sqlite3_prepare_v2(db_, "SELECT is_fallback FROM routing_rules LIMIT 1", -1, &checkStmt, nullptr) != SQLITE_OK) {
        ExecuteSQL("ALTER TABLE routing_rules ADD COLUMN is_fallback INTEGER DEFAULT 0;");
    } else {
        sqlite3_finalize(checkStmt);
    }

    // 分组名称规范化迁移：历史的 "默认分组" 迁移为 "默认"
    ExecuteSQL("UPDATE proxy_ports SET group_name = '默认' WHERE group_name = '默认分组';");
    ExecuteSQL("UPDATE routing_rules SET target_group = '默认' WHERE target_group = '默认分组';");
    
    // 默认历史流量留存期限配置 (总流量最多1年，节点流量最多60天)
    ExecuteSQL("INSERT OR IGNORE INTO system_config (key, value) VALUES ('traffic_retention_days', '365');");
    ExecuteSQL("INSERT OR IGNORE INTO system_config (key, value) VALUES ('port_traffic_retention_days', '60');");
    
    // 如果没有用户，创建默认管理员 (直接使用SQL避免死锁)
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM users", -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            if (sqlite3_column_int(stmt, 0) == 0) {
                sqlite3_finalize(stmt);
                // 直接插入默认用户，不调用AddUser()以避免死锁
                const char* insertSql = R"(
                    INSERT INTO users (username, password, allowed_ips, daily_limit, monthly_limit, enabled, allowed_targets)
                    VALUES ('admin', 'admin123', '*', 0, 0, 1, '*');
                )";
                ExecuteSQL(insertSql);
            } else {
                sqlite3_finalize(stmt);
            }
        } else {
            sqlite3_finalize(stmt);
        }
    }
    
    return true;
}

bool Database::ExecuteSQL(const std::string& sql) {
    char* errMsg = nullptr;
    int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        Utils::LogError("SQL error: " + std::string(errMsg));
        sqlite3_free(errMsg);
        return false;
    }
    return true;
}

// 用户管理
bool Database::AddUser(const UserInfo& user) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    const char* sql = R"(
        INSERT INTO users (username, password, allowed_ips, daily_limit, monthly_limit, enabled, remark, expiry_date, allowed_targets, priority)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, (SELECT COALESCE(MAX(priority), 0) + 1 FROM users));
    )";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, user.username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, user.password.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, user.allowedIPs.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, user.dailyLimit);
    sqlite3_bind_int64(stmt, 5, user.monthlyLimit);
    sqlite3_bind_int(stmt, 6, user.enabled ? 1 : 0);
    sqlite3_bind_text(stmt, 7, user.remark.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, user.expiryDate.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, user.allowedTargets.c_str(), -1, SQLITE_TRANSIENT);
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::UpdateUser(const UserInfo& user) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    const char* sql = R"(
        UPDATE users SET 
            username = ?, password = ?, allowed_ips = ?,
            daily_limit = ?, monthly_limit = ?, enabled = ?, remark = ?, expiry_date = ?,
            allowed_targets = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?;
    )";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, user.username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, user.password.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, user.allowedIPs.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, user.dailyLimit);
    sqlite3_bind_int64(stmt, 5, user.monthlyLimit);
    sqlite3_bind_int(stmt, 6, user.enabled ? 1 : 0);
    sqlite3_bind_text(stmt, 7, user.remark.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, user.expiryDate.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, user.allowedTargets.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 10, user.id);
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::DeleteUser(int userId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, "DELETE FROM users WHERE id = ?", -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, userId);
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::GetUser(int userId, UserInfo& user) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT id, username, password, allowed_ips, daily_limit, monthly_limit, enabled, remark, expiry_date, allowed_targets, priority, quota_reset_month, quota_offset_bytes, quota_reset_date, daily_quota_offset_bytes, created_at, updated_at FROM users WHERE id = ?";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, userId);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        user.id = sqlite3_column_int(stmt, 0);
        const char* uName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        user.username = uName ? uName : "";
        const char* uPass = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        user.password = uPass ? uPass : "";
        const char* ips = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        user.allowedIPs = ips ? ips : "*";
        user.dailyLimit = sqlite3_column_int64(stmt, 4);
        user.monthlyLimit = sqlite3_column_int64(stmt, 5);
        user.enabled = sqlite3_column_int(stmt, 6) != 0;
        const char* remark = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        user.remark = remark ? remark : "";
        const char* expiryDate = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
        user.expiryDate = expiryDate ? expiryDate : "";
        const char* allowedTargets = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
        user.allowedTargets = allowedTargets ? allowedTargets : "*";
        user.priority = sqlite3_column_int(stmt, 10);
        const char* qMonth = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));
        user.quotaResetMonth = qMonth ? qMonth : "";
        user.quotaOffsetBytes = sqlite3_column_int64(stmt, 12);
        const char* qDate = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 13));
        user.quotaResetDate = qDate ? qDate : "";
        user.dailyQuotaOffsetBytes = sqlite3_column_int64(stmt, 14);
        const char* created = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 15));
        user.createdAt = created ? created : "";
        const char* updated = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 16));
        user.updatedAt = updated ? updated : "";
        sqlite3_finalize(stmt);
        return true;
    }
    
    sqlite3_finalize(stmt);
    return false;
}

bool Database::GetUserByName(const std::string& username, UserInfo& user) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT id, username, password, allowed_ips, daily_limit, monthly_limit, enabled, remark, expiry_date, allowed_targets, priority, quota_reset_month, quota_offset_bytes, quota_reset_date, daily_quota_offset_bytes, created_at, updated_at FROM users WHERE username = ?";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        user.id = sqlite3_column_int(stmt, 0);
        const char* uName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        user.username = uName ? uName : "";
        const char* uPass = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        user.password = uPass ? uPass : "";
        const char* ips = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        user.allowedIPs = ips ? ips : "*";
        user.dailyLimit = sqlite3_column_int64(stmt, 4);
        user.monthlyLimit = sqlite3_column_int64(stmt, 5);
        user.enabled = sqlite3_column_int(stmt, 6) != 0;
        const char* remark = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        user.remark = remark ? remark : "";
        const char* expiryDate = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
        user.expiryDate = expiryDate ? expiryDate : "";
        const char* allowedTargets = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
        user.allowedTargets = allowedTargets ? allowedTargets : "*";
        user.priority = sqlite3_column_int(stmt, 10);
        const char* qMonth = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));
        user.quotaResetMonth = qMonth ? qMonth : "";
        user.quotaOffsetBytes = sqlite3_column_int64(stmt, 12);
        const char* qDate = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 13));
        user.quotaResetDate = qDate ? qDate : "";
        user.dailyQuotaOffsetBytes = sqlite3_column_int64(stmt, 14);
        const char* created = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 15));
        user.createdAt = created ? created : "";
        const char* updated = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 16));
        user.updatedAt = updated ? updated : "";
        sqlite3_finalize(stmt);
        return true;
    }
    
    sqlite3_finalize(stmt);
    return false;
}

std::vector<UserInfo> Database::GetAllUsers() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<UserInfo> users;
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT id, username, password, allowed_ips, daily_limit, monthly_limit, enabled, remark, expiry_date, allowed_targets, priority, quota_reset_month, quota_offset_bytes, quota_reset_date, daily_quota_offset_bytes, created_at, updated_at FROM users ORDER BY priority ASC, id ASC";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return users;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        UserInfo user;
        user.id = sqlite3_column_int(stmt, 0);
        const char* uName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        user.username = uName ? uName : "";
        const char* uPass = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        user.password = uPass ? uPass : "";
        const char* ips = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        user.allowedIPs = ips ? ips : "*";
        user.dailyLimit = sqlite3_column_int64(stmt, 4);
        user.monthlyLimit = sqlite3_column_int64(stmt, 5);
        user.enabled = sqlite3_column_int(stmt, 6) != 0;
        const char* remark = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        user.remark = remark ? remark : "";
        const char* expiryDate = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
        user.expiryDate = expiryDate ? expiryDate : "";
        const char* allowedTargets = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
        user.allowedTargets = allowedTargets ? allowedTargets : "*";
        user.priority = sqlite3_column_int(stmt, 10);
        const char* qMonth = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));
        user.quotaResetMonth = qMonth ? qMonth : "";
        user.quotaOffsetBytes = sqlite3_column_int64(stmt, 12);
        const char* qDate = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 13));
        user.quotaResetDate = qDate ? qDate : "";
        user.dailyQuotaOffsetBytes = sqlite3_column_int64(stmt, 14);
        const char* created = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 15));
        user.createdAt = created ? created : "";
        const char* updated = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 16));
        user.updatedAt = updated ? updated : "";
        users.push_back(user);
    }
    
    sqlite3_finalize(stmt);
    return users;
}

bool Database::MoveUserUp(int userId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto users = GetAllUsers();
    int targetIdx = -1;
    for (size_t i = 0; i < users.size(); ++i) {
        if (users[i].id == userId) {
            targetIdx = (int)i;
            break;
        }
    }
    if (targetIdx <= 0) return false;

    std::swap(users[targetIdx], users[targetIdx - 1]);
    for (size_t i = 0; i < users.size(); ++i) {
        int newPriority = (int)(i + 1);
        std::string sql = "UPDATE users SET priority = " + std::to_string(newPriority) + " WHERE id = " + std::to_string(users[i].id) + ";";
        ExecuteSQL(sql);
    }
    return true;
}

bool Database::MoveUserDown(int userId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto users = GetAllUsers();
    int targetIdx = -1;
    for (size_t i = 0; i < users.size(); ++i) {
        if (users[i].id == userId) {
            targetIdx = (int)i;
            break;
        }
    }
    if (targetIdx < 0 || targetIdx >= (int)users.size() - 1) return false;

    std::swap(users[targetIdx], users[targetIdx + 1]);
    for (size_t i = 0; i < users.size(); ++i) {
        int newPriority = (int)(i + 1);
        std::string sql = "UPDATE users SET priority = " + std::to_string(newPriority) + " WHERE id = " + std::to_string(users[i].id) + ";";
        ExecuteSQL(sql);
    }
    return true;
}

// 代理节点智能分组辅助函数
std::string Database::InferNodeGroup(const std::string& name, const std::string& desc) {
    std::string combined = name + " " + desc;
    if (combined.find("🇯🇵") != std::string::npos || combined.find("日本") != std::string::npos || combined.find("JP") != std::string::npos || combined.find("Japan") != std::string::npos) return "日本节点";
    if (combined.find("🇭🇰") != std::string::npos || combined.find("香港") != std::string::npos || combined.find("HK") != std::string::npos || combined.find("HongKong") != std::string::npos) return "香港节点";
    if (combined.find("🇺🇸") != std::string::npos || combined.find("美国") != std::string::npos || combined.find("US") != std::string::npos || combined.find("United States") != std::string::npos) return "美国节点";
    if (combined.find("🇸🇬") != std::string::npos || combined.find("新加坡") != std::string::npos || combined.find("SG") != std::string::npos || combined.find("Singapore") != std::string::npos) return "新加坡节点";
    if (combined.find("🇹🇼") != std::string::npos || combined.find("台湾") != std::string::npos || combined.find("TW") != std::string::npos || combined.find("Taiwan") != std::string::npos) return "台湾节点";
    if (combined.find("🇰🇷") != std::string::npos || combined.find("韩国") != std::string::npos || combined.find("KR") != std::string::npos || combined.find("Korea") != std::string::npos) return "韩国节点";
    if (combined.find("🇬🇧") != std::string::npos || combined.find("英国") != std::string::npos || combined.find("UK") != std::string::npos || combined.find("Britain") != std::string::npos) return "英国节点";
    if (combined.find("🇩🇪") != std::string::npos || combined.find("德国") != std::string::npos || combined.find("DE") != std::string::npos || combined.find("Germany") != std::string::npos) return "德国节点";
    return "默认";
}

// 代理端口管理
bool Database::AddProxyPort(const ProxyPort& port) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    std::string gName = port.groupName.empty() ? InferNodeGroup(port.clashNodeName, port.description) : port.groupName;

    const char* sql = R"(
        INSERT INTO proxy_ports (listen_port, upstream_type, upstream_host, upstream_port, 
                                 upstream_user, upstream_pass, enabled, auto_check, description, xray_config, clash_config,
                                 clash_subscription_id, clash_node_name, allowed_targets, group_name, priority)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, (SELECT COALESCE(MAX(priority), 0) + 1 FROM proxy_ports));
    )";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    // listen_port 为 0 或负数时绑定 NULL
    if (port.listenPort > 0) {
        sqlite3_bind_int(stmt, 1, port.listenPort);
    } else {
        sqlite3_bind_null(stmt, 1);
    }
    sqlite3_bind_text(stmt, 2, port.upstreamType.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, port.upstreamHost.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, port.upstreamPort);
    sqlite3_bind_text(stmt, 5, port.upstreamUser.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, port.upstreamPass.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 7, port.enabled ? 1 : 0);
    sqlite3_bind_int(stmt, 8, port.autoCheck ? 1 : 0);
    sqlite3_bind_text(stmt, 9, port.description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 10, port.xrayConfig.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 11, port.clashConfig.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 12, port.clashSubscriptionId);
    sqlite3_bind_text(stmt, 13, port.clashNodeName.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 14, port.allowedTargets.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 15, gName.c_str(), -1, SQLITE_TRANSIENT);
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::UpdateProxyPort(const ProxyPort& port) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    std::string gName = port.groupName.empty() ? InferNodeGroup(port.clashNodeName, port.description) : port.groupName;

    const char* sql = R"(
        UPDATE proxy_ports SET 
            listen_port = ?, upstream_type = ?, upstream_host = ?, upstream_port = ?,
            upstream_user = ?, upstream_pass = ?, enabled = ?, auto_check = ?, description = ?, xray_config = ?, clash_config = ?,
            clash_subscription_id = ?, clash_node_name = ?, allowed_targets = ?, group_name = ?
        WHERE id = ?;
    )";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    // listen_port 为 0 或负数时绑定 NULL
    if (port.listenPort > 0) {
        sqlite3_bind_int(stmt, 1, port.listenPort);
    } else {
        sqlite3_bind_null(stmt, 1);
    }
    sqlite3_bind_text(stmt, 2, port.upstreamType.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, port.upstreamHost.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, port.upstreamPort);
    sqlite3_bind_text(stmt, 5, port.upstreamUser.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, port.upstreamPass.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 7, port.enabled ? 1 : 0);
    sqlite3_bind_int(stmt, 8, port.autoCheck ? 1 : 0);
    sqlite3_bind_text(stmt, 9, port.description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 10, port.xrayConfig.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 11, port.clashConfig.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 12, port.clashSubscriptionId);
    sqlite3_bind_text(stmt, 13, port.clashNodeName.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 14, port.allowedTargets.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 15, gName.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 16, port.id);
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::DeleteProxyPort(int portId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, "DELETE FROM proxy_ports WHERE id = ?", -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, portId);
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::GetProxyPort(int portId, ProxyPort& port) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT id, listen_port, upstream_type, upstream_host, upstream_port, upstream_user, upstream_pass, enabled, description, priority, created_at, xray_config, clash_config, clash_subscription_id, clash_node_name, auto_check, allowed_targets, group_name FROM proxy_ports WHERE id = ?";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, portId);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        port.id = sqlite3_column_int(stmt, 0);
        port.listenPort = sqlite3_column_int(stmt, 1);
        const char* type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        port.upstreamType = type ? type : "";
        const char* host = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        port.upstreamHost = host ? host : "";
        port.upstreamPort = sqlite3_column_int(stmt, 4);
        const char* user = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        port.upstreamUser = user ? user : "";
        const char* pass = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        port.upstreamPass = pass ? pass : "";
        port.enabled = sqlite3_column_int(stmt, 7) != 0;
        const char* desc = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
        port.description = desc ? desc : "";
        port.priority = sqlite3_column_int(stmt, 9);
        const char* created = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
        port.createdAt = created ? created : "";
        const char* xrayConf = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));
        port.xrayConfig = xrayConf ? xrayConf : "";
        const char* clashConf = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 12));
        port.clashConfig = clashConf ? clashConf : "";
        port.clashSubscriptionId = sqlite3_column_int(stmt, 13);
        const char* nodeName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 14));
        port.clashNodeName = nodeName ? nodeName : "";
        port.autoCheck = sqlite3_column_int(stmt, 15) != 0;
        const char* allowedTgts = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 16));
        port.allowedTargets = allowedTgts ? allowedTgts : "*";
        const char* grp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 17));
        port.groupName = grp ? grp : "";
        if (port.groupName.empty()) {
            port.groupName = InferNodeGroup(port.clashNodeName, port.description);
        }
        sqlite3_finalize(stmt);
        return true;
    }
    
    sqlite3_finalize(stmt);
    return false;
}

std::vector<ProxyPort> Database::GetAllProxyPorts() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<ProxyPort> ports;
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT id, listen_port, upstream_type, upstream_host, upstream_port, upstream_user, upstream_pass, enabled, description, priority, created_at, xray_config, clash_config, clash_subscription_id, clash_node_name, auto_check, allowed_targets, group_name FROM proxy_ports ORDER BY priority ASC, listen_port ASC";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return ports;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ProxyPort port;
        port.id = sqlite3_column_int(stmt, 0);
        port.listenPort = sqlite3_column_int(stmt, 1);
        const char* type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        port.upstreamType = type ? type : "";
        const char* host = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        port.upstreamHost = host ? host : "";
        port.upstreamPort = sqlite3_column_int(stmt, 4);
        const char* user = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        port.upstreamUser = user ? user : "";
        const char* pass = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        port.upstreamPass = pass ? pass : "";
        port.enabled = sqlite3_column_int(stmt, 7) != 0;
        const char* desc = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
        port.description = desc ? desc : "";
        port.priority = sqlite3_column_int(stmt, 9);
        const char* created = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
        port.createdAt = created ? created : "";
        const char* xrayConf = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));
        port.xrayConfig = xrayConf ? xrayConf : "";
        const char* clashConf = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 12));
        port.clashConfig = clashConf ? clashConf : "";
        port.clashSubscriptionId = sqlite3_column_int(stmt, 13);
        const char* nodeName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 14));
        port.clashNodeName = nodeName ? nodeName : "";
        port.autoCheck = sqlite3_column_int(stmt, 15) != 0;
        const char* allowedTgts = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 16));
        port.allowedTargets = allowedTgts ? allowedTgts : "*";
        const char* grp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 17));
        port.groupName = grp ? grp : "";
        if (port.groupName.empty()) {
            port.groupName = InferNodeGroup(port.clashNodeName, port.description);
        }
        ports.push_back(port);
    }
    
    sqlite3_finalize(stmt);
    return ports;
}

std::vector<ProxyPort> Database::GetEnabledProxyPorts() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<ProxyPort> ports;
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT id, listen_port, upstream_type, upstream_host, upstream_port, upstream_user, upstream_pass, enabled, description, priority, created_at, xray_config, clash_config, clash_subscription_id, clash_node_name, auto_check, allowed_targets, group_name FROM proxy_ports WHERE enabled = 1 ORDER BY priority ASC, listen_port ASC";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return ports;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ProxyPort port;
        port.id = sqlite3_column_int(stmt, 0);
        port.listenPort = sqlite3_column_int(stmt, 1);
        const char* type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        port.upstreamType = type ? type : "";
        const char* host = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        port.upstreamHost = host ? host : "";
        port.upstreamPort = sqlite3_column_int(stmt, 4);
        const char* user = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        port.upstreamUser = user ? user : "";
        const char* pass = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        port.upstreamPass = pass ? pass : "";
        port.enabled = true;
        const char* desc = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
        port.description = desc ? desc : "";
        port.priority = sqlite3_column_int(stmt, 9);
        const char* created = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
        port.createdAt = created ? created : "";
        const char* xrayConf = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));
        port.xrayConfig = xrayConf ? xrayConf : "";
        const char* clashConf = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 12));
        port.clashConfig = clashConf ? clashConf : "";
        port.clashSubscriptionId = sqlite3_column_int(stmt, 13);
        const char* nodeName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 14));
        port.clashNodeName = nodeName ? nodeName : "";
        port.autoCheck = sqlite3_column_int(stmt, 15) != 0;
        const char* allowedTgts2 = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 16));
        port.allowedTargets = allowedTgts2 ? allowedTgts2 : "*";
        const char* grp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 17));
        port.groupName = grp ? grp : "";
        if (port.groupName.empty()) {
            port.groupName = InferNodeGroup(port.clashNodeName, port.description);
        }
        ports.push_back(port);
    }
    
    sqlite3_finalize(stmt);
    return ports;
}

void Database::RepairClashPorts() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto ports = GetAllProxyPorts();
    for (auto& p : ports) {
        if (p.upstreamType == "clash") {
            bool needRepair = (p.upstreamHost.empty() || p.upstreamPort <= 0 || p.clashConfig.empty() || p.clashConfig.find("mode: global") != std::string::npos);
            if (needRepair) {
                std::string contentToParse = p.clashConfig;
                if ((contentToParse.empty() || contentToParse.find("proxies:") == std::string::npos) && p.clashSubscriptionId > 0) {
                    ClashSubscription sub;
                    if (GetSubscription(p.clashSubscriptionId, sub)) {
                        contentToParse = sub.rawContent;
                    }
                }
                if (!contentToParse.empty()) {
                    auto nodes = ClashManager::ParseSubscriptionNodes(contentToParse);
                    for (const auto& node : nodes) {
                        bool match = (nodes.size() == 1) || 
                                     (!p.clashNodeName.empty() && (node.name == p.clashNodeName || node.name.find(p.clashNodeName) != std::string::npos || p.clashNodeName.find(node.name) != std::string::npos)) ||
                                     (!p.description.empty() && (p.description == node.name || p.description.find(node.name) != std::string::npos || node.name.find(p.description) != std::string::npos));
                        if (match && !node.server.empty() && node.port > 0) {
                            p.upstreamHost = node.server;
                            p.upstreamPort = node.port;
                            if (p.clashNodeName.empty()) p.clashNodeName = node.name;
                            p.clashConfig = ClashManager::GenerateNodeConfig(node, 0);
                            UpdateProxyPort(p);
                            Utils::Log("Auto-repaired clash port #" + std::to_string(p.id) + ": " + p.upstreamHost + ":" + std::to_string(p.upstreamPort));
                            break;
                        }
                    }
                }
            }
        }
    }
}

// 流量统计
bool Database::RecordTraffic(int userId, int64_t uploadBytes, int64_t downloadBytes) {
    if (userId == 0) return true; // 不记录免认证用户的流量历史
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    std::string today = Utils::GetCurrentDate();
    
    // 使用UPSERT语法
    const char* sql = R"(
        INSERT INTO traffic_records (user_id, date, upload_bytes, download_bytes, updated_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(user_id, date) DO UPDATE SET
            upload_bytes = upload_bytes + excluded.upload_bytes,
            download_bytes = download_bytes + excluded.download_bytes,
            updated_at = CURRENT_TIMESTAMP;
    )";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, userId);
    sqlite3_bind_text(stmt, 2, today.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, uploadBytes);
    sqlite3_bind_int64(stmt, 4, downloadBytes);
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::RecordPortTraffic(int portId, int64_t uploadBytes, int64_t downloadBytes) {
    if (portId <= 0) return true;
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    std::string today = Utils::GetCurrentDate();
    
    const char* sql = R"(
        INSERT INTO port_traffic_records (port_id, date, upload_bytes, download_bytes, updated_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(port_id, date) DO UPDATE SET
            upload_bytes = upload_bytes + excluded.upload_bytes,
            download_bytes = download_bytes + excluded.download_bytes,
            updated_at = CURRENT_TIMESTAMP;
    )";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, portId);
    sqlite3_bind_text(stmt, 2, today.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, uploadBytes);
    sqlite3_bind_int64(stmt, 4, downloadBytes);
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::GetDailyTraffic(int userId, const std::string& date, TrafficRecord& record) {
    bool found = false;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, "SELECT * FROM traffic_records WHERE user_id = ? AND date = ?", -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, userId);
            sqlite3_bind_text(stmt, 2, date.c_str(), -1, SQLITE_TRANSIENT);
            
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                record.id = sqlite3_column_int(stmt, 0);
                record.userId = sqlite3_column_int(stmt, 1);
                record.date = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
                record.uploadBytes = sqlite3_column_int64(stmt, 3);
                record.downloadBytes = sqlite3_column_int64(stmt, 4);
                const char* updated = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
                record.updatedAt = updated ? updated : "";
                found = true;
            }
            sqlite3_finalize(stmt);
        }
    }
    
    if (date == Utils::GetCurrentDate()) {
        int64_t unpersistedUpload = 0, unpersistedDownload = 0;
        TrafficMonitor::Instance().GetUserUnpersistedTraffic(userId, unpersistedUpload, unpersistedDownload);
        if (found) {
            record.uploadBytes += unpersistedUpload;
            record.downloadBytes += unpersistedDownload;
        } else if (unpersistedUpload > 0 || unpersistedDownload > 0) {
            record.id = 0;
            record.userId = userId;
            record.date = date;
            record.uploadBytes = unpersistedUpload;
            record.downloadBytes = unpersistedDownload;
            record.updatedAt = "";
            found = true;
        }
    }
    
    return found;
}

bool Database::GetMonthlyTraffic(int userId, const std::string& month, int64_t& upload, int64_t& download) {
    std::string pattern = month + "%";
    upload = 0;
    download = 0;
    bool found = false;
    
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, 
            "SELECT SUM(upload_bytes), SUM(download_bytes) FROM traffic_records WHERE user_id = ? AND date LIKE ?", 
            -1, &stmt, nullptr) == SQLITE_OK) {
            
            sqlite3_bind_int(stmt, 1, userId);
            sqlite3_bind_text(stmt, 2, pattern.c_str(), -1, SQLITE_TRANSIENT);
            
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                upload = sqlite3_column_int64(stmt, 0);
                download = sqlite3_column_int64(stmt, 1);
                found = true;
            }
            sqlite3_finalize(stmt);
        }
    }
    
    if (month == Utils::GetCurrentMonth()) {
        int64_t unpersistedUpload = 0, unpersistedDownload = 0;
        TrafficMonitor::Instance().GetUserUnpersistedTraffic(userId, unpersistedUpload, unpersistedDownload);
        upload += unpersistedUpload;
        download += unpersistedDownload;
        found = true;
    }
    
    return found;
}

bool Database::GetUserWeeklyTraffic(int userId, const std::string& weekStartDate, const std::string& today, int64_t& upload, int64_t& download) {
    upload = 0;
    download = 0;
    bool found = false;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_,
            "SELECT SUM(upload_bytes), SUM(download_bytes) FROM traffic_records WHERE user_id = ? AND date >= ? AND date <= ?",
            -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, userId);
            sqlite3_bind_text(stmt, 2, weekStartDate.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 3, today.c_str(), -1, SQLITE_TRANSIENT);
            
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                upload = sqlite3_column_int64(stmt, 0);
                download = sqlite3_column_int64(stmt, 1);
                found = true;
            }
            sqlite3_finalize(stmt);
        }
    }
    
    // 包含当前内存尚未持久化的 session 流量
    int64_t unpUp = 0, unpDown = 0;
    TrafficMonitor::Instance().GetUserUnpersistedTraffic(userId, unpUp, unpDown);
    upload += unpUp;
    download += unpDown;
    return found || (upload > 0 || download > 0);
}

bool Database::GetPortDailyTraffic(int portId, const std::string& date, int64_t& upload, int64_t& download) {
    upload = 0;
    download = 0;
    bool found = false;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, "SELECT upload_bytes, download_bytes FROM port_traffic_records WHERE port_id = ? AND date = ?", -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, portId);
            sqlite3_bind_text(stmt, 2, date.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                upload = sqlite3_column_int64(stmt, 0);
                download = sqlite3_column_int64(stmt, 1);
                found = true;
            }
            sqlite3_finalize(stmt);
        }
    }
    if (date == Utils::GetCurrentDate()) {
        int64_t unpUp = 0, unpDown = 0;
        TrafficMonitor::Instance().GetPortUnpersistedTraffic(portId, unpUp, unpDown);
        upload += unpUp;
        download += unpDown;
    }
    return found;
}

bool Database::GetPortWeeklyTraffic(int portId, const std::string& weekStartDate, const std::string& today, int64_t& upload, int64_t& download) {
    upload = 0;
    download = 0;
    bool found = false;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_,
            "SELECT SUM(upload_bytes), SUM(download_bytes) FROM port_traffic_records WHERE port_id = ? AND date >= ? AND date <= ?",
            -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, portId);
            sqlite3_bind_text(stmt, 2, weekStartDate.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 3, today.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                upload = sqlite3_column_int64(stmt, 0);
                download = sqlite3_column_int64(stmt, 1);
                found = true;
            }
            sqlite3_finalize(stmt);
        }
    }
    int64_t unpUp = 0, unpDown = 0;
    TrafficMonitor::Instance().GetPortUnpersistedTraffic(portId, unpUp, unpDown);
    upload += unpUp;
    download += unpDown;
    return found || (upload > 0 || download > 0);
}

bool Database::GetPortMonthlyTraffic(int portId, const std::string& month, int64_t& upload, int64_t& download) {
    std::string pattern = month + "%";
    upload = 0;
    download = 0;
    bool found = false;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_,
            "SELECT SUM(upload_bytes), SUM(download_bytes) FROM port_traffic_records WHERE port_id = ? AND date LIKE ?",
            -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, portId);
            sqlite3_bind_text(stmt, 2, pattern.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                upload = sqlite3_column_int64(stmt, 0);
                download = sqlite3_column_int64(stmt, 1);
                found = true;
            }
            sqlite3_finalize(stmt);
        }
    }
    if (month == Utils::GetCurrentMonth()) {
        int64_t unpUp = 0, unpDown = 0;
        TrafficMonitor::Instance().GetPortUnpersistedTraffic(portId, unpUp, unpDown);
        upload += unpUp;
        download += unpDown;
    }
    return found;
}

bool Database::GetPortLastMonthTraffic(int portId, const std::string& lastMonth, int64_t& upload, int64_t& download) {
    std::string pattern = lastMonth + "%";
    upload = 0;
    download = 0;
    bool found = false;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_,
            "SELECT SUM(upload_bytes), SUM(download_bytes) FROM port_traffic_records WHERE port_id = ? AND date LIKE ?",
            -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, portId);
            sqlite3_bind_text(stmt, 2, pattern.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                upload = sqlite3_column_int64(stmt, 0);
                download = sqlite3_column_int64(stmt, 1);
                found = true;
            }
            sqlite3_finalize(stmt);
        }
    }
    return found;
}

std::vector<DailyTrafficSummary> Database::GetDailyTrafficHistory(int days, int userId) {
    std::vector<DailyTrafficSummary> result;
    auto dates = Utils::GetPastDates(days);
    if (dates.empty()) return result;
    
    std::string startDate = dates.front();
    std::string endDate = dates.back();
    
    std::map<std::string, std::pair<int64_t, int64_t>> mapData;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        sqlite3_stmt* stmt = nullptr;
        if (userId > 0) {
            const char* sql = "SELECT date, SUM(upload_bytes), SUM(download_bytes) FROM traffic_records WHERE user_id = ? AND date >= ? AND date <= ? GROUP BY date";
            if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, userId);
                sqlite3_bind_text(stmt, 2, startDate.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 3, endDate.c_str(), -1, SQLITE_TRANSIENT);
            }
        } else {
            const char* sql = "SELECT date, SUM(upload_bytes), SUM(download_bytes) FROM traffic_records WHERE date >= ? AND date <= ? GROUP BY date";
            if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, startDate.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 2, endDate.c_str(), -1, SQLITE_TRANSIENT);
            }
        }
        
        if (stmt) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* dText = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                if (dText) {
                    int64_t up = sqlite3_column_int64(stmt, 1);
                    int64_t down = sqlite3_column_int64(stmt, 2);
                    mapData[dText] = {up, down};
                }
            }
            sqlite3_finalize(stmt);
        }
    }
    
    // 对今天的未持久化增量进行补充
    std::string today = Utils::GetCurrentDate();
    int64_t unpUp = 0, unpDown = 0;
    if (userId > 0) {
        TrafficMonitor::Instance().GetUserUnpersistedTraffic(userId, unpUp, unpDown);
    } else {
        TrafficMonitor::Instance().GetAllUnpersistedTraffic(unpUp, unpDown);
    }
    mapData[today].first += unpUp;
    mapData[today].second += unpDown;
    
    // 依次填充返回每一个连续的自然日
    for (const auto& d : dates) {
        DailyTrafficSummary s;
        s.date = d;
        auto it = mapData.find(d);
        if (it != mapData.end()) {
            s.uploadBytes = it->second.first;
            s.downloadBytes = it->second.second;
        }
        s.totalBytes = s.uploadBytes + s.downloadBytes;
        result.push_back(s);
    }
    return result;
}

std::vector<TrafficTrendItem> Database::GetTrafficTrend(const std::string& mode, int count, int userId) {
    std::vector<TrafficTrendItem> result;

    // 获取未持久化的内存实时增量流量
    std::string today = Utils::GetCurrentDate();
    int64_t unpUp = 0, unpDown = 0;
    if (userId > 0) {
        TrafficMonitor::Instance().GetUserUnpersistedTraffic(userId, unpUp, unpDown);
    } else {
        TrafficMonitor::Instance().GetAllUnpersistedTraffic(unpUp, unpDown);
    }

    if (mode == "month") {
        if (count <= 0) count = 12;
        if (count > 36) count = 36;

        time_t now = time(nullptr);
        struct tm tm_now;
#if defined(_WIN32)
        localtime_s(&tm_now, &now);
#else
        localtime_r(&now, &tm_now);
#endif
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

        std::map<std::string, std::pair<int64_t, int64_t>> monthMap;
        {
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            sqlite3_stmt* stmt = nullptr;
            if (userId > 0) {
                const char* sql = "SELECT substr(date, 1, 7) AS ym, SUM(upload_bytes), SUM(download_bytes) FROM traffic_records WHERE date >= ? AND date <= ? AND user_id = ? GROUP BY ym";
                if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
                    sqlite3_bind_text(stmt, 1, startMonth.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 2, endMonth.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_int(stmt, 3, userId);
                }
            } else {
                const char* sql = "SELECT substr(date, 1, 7) AS ym, SUM(upload_bytes), SUM(download_bytes) FROM traffic_records WHERE date >= ? AND date <= ? GROUP BY ym";
                if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
                    sqlite3_bind_text(stmt, 1, startMonth.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 2, endMonth.c_str(), -1, SQLITE_TRANSIENT);
                }
            }

            if (stmt) {
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
        }

        // 加上当月实时未持久化流量
        std::string curYm = today.length() >= 7 ? today.substr(0, 7) : "";
        if (!curYm.empty()) {
            monthMap[curYm].first += unpUp;
            monthMap[curYm].second += unpDown;
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
#if defined(_WIN32)
        localtime_s(&tm_now, &now);
#else
        localtime_r(&now, &tm_now);
#endif
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
#if defined(_WIN32)
                localtime_s(&tm_d, &tDay);
#else
                localtime_r(&tDay, &tm_d);
#endif
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

        std::map<std::string, std::pair<int64_t, int64_t>> dayMap;
        {
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            sqlite3_stmt* stmt = nullptr;
            if (userId > 0) {
                const char* sql = "SELECT date, SUM(upload_bytes), SUM(download_bytes) FROM traffic_records WHERE date >= ? AND date <= ? AND user_id = ? GROUP BY date";
                if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
                    sqlite3_bind_text(stmt, 1, overallStart.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 2, overallEnd.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_int(stmt, 3, userId);
                }
            } else {
                const char* sql = "SELECT date, SUM(upload_bytes), SUM(download_bytes) FROM traffic_records WHERE date >= ? AND date <= ? GROUP BY date";
                if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
                    sqlite3_bind_text(stmt, 1, overallStart.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 2, overallEnd.c_str(), -1, SQLITE_TRANSIENT);
                }
            }

            if (stmt) {
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
        }

        // 加上当日未持久化流量
        dayMap[today].first += unpUp;
        dayMap[today].second += unpDown;

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

        std::map<std::string, std::pair<int64_t, int64_t>> dayMap;
        {
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            sqlite3_stmt* stmt = nullptr;
            if (userId > 0) {
                const char* sql = "SELECT date, SUM(upload_bytes), SUM(download_bytes) FROM traffic_records WHERE date >= ? AND date <= ? AND user_id = ? GROUP BY date";
                if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
                    sqlite3_bind_text(stmt, 1, overallStart.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 2, overallEnd.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_int(stmt, 3, userId);
                }
            } else {
                const char* sql = "SELECT date, SUM(upload_bytes), SUM(download_bytes) FROM traffic_records WHERE date >= ? AND date <= ? GROUP BY date";
                if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
                    sqlite3_bind_text(stmt, 1, overallStart.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 2, overallEnd.c_str(), -1, SQLITE_TRANSIENT);
                }
            }

            if (stmt) {
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
        }

        // 加上当日未持久化流量
        dayMap[today].first += unpUp;
        dayMap[today].second += unpDown;

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

std::vector<DailyTrafficSummary> Database::GetPortDailyTrafficHistory(int days, int portId) {
    std::vector<DailyTrafficSummary> result;
    if (days <= 0) days = 30;
    auto dates = Utils::GetPastDates(days);
    if (dates.empty()) return result;
    
    std::string startDate = dates.front();
    std::string endDate = dates.back();
    
    std::map<std::string, std::pair<int64_t, int64_t>> mapData;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        sqlite3_stmt* stmt = nullptr;
        if (portId > 0) {
            const char* sql = "SELECT date, SUM(upload_bytes), SUM(download_bytes) FROM port_traffic_records WHERE port_id = ? AND date >= ? AND date <= ? GROUP BY date";
            if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, portId);
                sqlite3_bind_text(stmt, 2, startDate.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 3, endDate.c_str(), -1, SQLITE_TRANSIENT);
            }
        } else {
            const char* sql = "SELECT date, SUM(upload_bytes), SUM(download_bytes) FROM port_traffic_records WHERE date >= ? AND date <= ? GROUP BY date";
            if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, startDate.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 2, endDate.c_str(), -1, SQLITE_TRANSIENT);
            }
        }
        
        if (stmt) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* dText = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                if (dText) {
                    int64_t up = sqlite3_column_int64(stmt, 1);
                    int64_t down = sqlite3_column_int64(stmt, 2);
                    mapData[dText] = {up, down};
                }
            }
            sqlite3_finalize(stmt);
        }
    }
    
    // 对今天的未持久化增量进行补充
    std::string today = Utils::GetCurrentDate();
    int64_t unpUp = 0, unpDown = 0;
    if (portId > 0) {
        TrafficMonitor::Instance().GetPortUnpersistedTraffic(portId, unpUp, unpDown);
    } else {
        TrafficMonitor::Instance().GetAllPortUnpersistedTraffic(unpUp, unpDown);
    }
    mapData[today].first += unpUp;
    mapData[today].second += unpDown;
    
    // 依次填充返回每一个连续的自然日
    for (const auto& d : dates) {
        DailyTrafficSummary s;
        s.date = d;
        auto it = mapData.find(d);
        if (it != mapData.end()) {
            s.uploadBytes = it->second.first;
            s.downloadBytes = it->second.second;
        }
        s.totalBytes = s.uploadBytes + s.downloadBytes;
        result.push_back(s);
    }
    return result;
}

std::vector<MonthlyTrafficSummary> Database::GetPortAnnualTrafficHistory(int year, int portId) {
    std::vector<MonthlyTrafficSummary> result;
    if (year <= 0) {
        try {
            year = std::stoi(Utils::GetCurrentDate().substr(0, 4));
        } catch (...) {
            year = 2026;
        }
    }
    std::string yearStr = std::to_string(year);
    std::string startDate = yearStr + "-01-01";
    std::string endDate = yearStr + "-12-31";

    std::map<std::string, std::pair<int64_t, int64_t>> monthMap;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        sqlite3_stmt* stmt = nullptr;
        if (portId > 0) {
            const char* sql = "SELECT substr(date, 1, 7) AS m, SUM(upload_bytes), SUM(download_bytes) FROM port_traffic_records WHERE port_id = ? AND date >= ? AND date <= ? GROUP BY m";
            if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, portId);
                sqlite3_bind_text(stmt, 2, startDate.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 3, endDate.c_str(), -1, SQLITE_TRANSIENT);
            }
        } else {
            const char* sql = "SELECT substr(date, 1, 7) AS m, SUM(upload_bytes), SUM(download_bytes) FROM port_traffic_records WHERE date >= ? AND date <= ? GROUP BY m";
            if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, startDate.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 2, endDate.c_str(), -1, SQLITE_TRANSIENT);
            }
        }

        if (stmt) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* mText = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                if (mText) {
                    int64_t up = sqlite3_column_int64(stmt, 1);
                    int64_t down = sqlite3_column_int64(stmt, 2);
                    monthMap[mText] = {up, down};
                }
            }
            sqlite3_finalize(stmt);
        }
    }

    // 若当前查询年份是今年，则将本月未持久化的内存增量加到当前月份
    std::string curDate = Utils::GetCurrentDate();
    if (curDate.size() >= 7 && curDate.substr(0, 4) == yearStr) {
        std::string curMonth = curDate.substr(0, 7);
        int64_t unpUp = 0, unpDown = 0;
        if (portId > 0) {
            TrafficMonitor::Instance().GetPortUnpersistedTraffic(portId, unpUp, unpDown);
        } else {
            TrafficMonitor::Instance().GetAllPortUnpersistedTraffic(unpUp, unpDown);
        }
        monthMap[curMonth].first += unpUp;
        monthMap[curMonth].second += unpDown;
    }

    // 生成从 1 月至 12 月的完整年度序列
    for (int m = 1; m <= 12; ++m) {
        std::ostringstream oss;
        oss << yearStr << "-" << std::setw(2) << std::setfill('0') << m;
        std::string mStr = oss.str();
        MonthlyTrafficSummary summary;
        summary.month = mStr;
        auto it = monthMap.find(mStr);
        if (it != monthMap.end()) {
            summary.uploadBytes = it->second.first;
            summary.downloadBytes = it->second.second;
        }
        summary.totalBytes = summary.uploadBytes + summary.downloadBytes;
        result.push_back(summary);
    }
    return result;
}

std::vector<int> Database::GetPortTrafficYears() {
    std::set<int> yearSet;
    int currentYear = 2026;
    try {
        currentYear = std::stoi(Utils::GetCurrentDate().substr(0, 4));
    } catch (...) {}
    yearSet.insert(currentYear);

    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        sqlite3_stmt* stmt = nullptr;
        const char* sql = "SELECT DISTINCT substr(date, 1, 4) FROM port_traffic_records";
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* yText = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                if (yText && std::strlen(yText) == 4) {
                    try {
                        yearSet.insert(std::stoi(yText));
                    } catch (...) {}
                }
            }
            sqlite3_finalize(stmt);
        }
    }

    std::vector<int> years(yearSet.rbegin(), yearSet.rend());
    return years;
}

std::vector<TrafficRecord> Database::GetUserTrafficHistory(int userId, int days) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<TrafficRecord> records;
    
    std::string sql = "SELECT * FROM traffic_records WHERE user_id = ? ORDER BY date DESC LIMIT ?";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        return records;
    }
    
    sqlite3_bind_int(stmt, 1, userId);
    sqlite3_bind_int(stmt, 2, days);
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        TrafficRecord record;
        record.id = sqlite3_column_int(stmt, 0);
        record.userId = sqlite3_column_int(stmt, 1);
        record.date = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        record.uploadBytes = sqlite3_column_int64(stmt, 3);
        record.downloadBytes = sqlite3_column_int64(stmt, 4);
        const char* updated = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        record.updatedAt = updated ? updated : "";
        records.push_back(record);
    }
    
    sqlite3_finalize(stmt);
    return records;
}

std::vector<TrafficRecord> Database::GetAllUsersTrafficToday() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<TrafficRecord> records;
    
    std::string today = Utils::GetCurrentDate();
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, "SELECT * FROM traffic_records WHERE date = ?", -1, &stmt, nullptr) != SQLITE_OK) {
        return records;
    }
    
    sqlite3_bind_text(stmt, 1, today.c_str(), -1, SQLITE_TRANSIENT);
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        TrafficRecord record;
        record.id = sqlite3_column_int(stmt, 0);
        record.userId = sqlite3_column_int(stmt, 1);
        record.date = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        record.uploadBytes = sqlite3_column_int64(stmt, 3);
        record.downloadBytes = sqlite3_column_int64(stmt, 4);
        const char* updated = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        record.updatedAt = updated ? updated : "";
        records.push_back(record);
    }
    
    sqlite3_finalize(stmt);
    return records;
}

int64_t Database::GetUserDailyUsage(int userId) {
    int64_t rawUsage = 0;
    TrafficRecord record;
    if (GetDailyTraffic(userId, Utils::GetCurrentDate(), record)) {
        rawUsage = record.uploadBytes + record.downloadBytes;
    }
    UserInfo user;
    if (GetUser(userId, user)) {
        if (user.quotaResetDate == Utils::GetCurrentDate()) {
            return std::max<int64_t>(0, rawUsage - user.dailyQuotaOffsetBytes);
        }
    }
    return rawUsage;
}

int64_t Database::GetUserMonthlyUsage(int userId) {
    int64_t upload = 0, download = 0;
    int64_t rawUsage = 0;
    if (GetMonthlyTraffic(userId, Utils::GetCurrentMonth(), upload, download)) {
        rawUsage = upload + download;
    }
    UserInfo user;
    if (GetUser(userId, user)) {
        if (user.quotaResetMonth == Utils::GetCurrentMonth()) {
            return std::max<int64_t>(0, rawUsage - user.quotaOffsetBytes);
        }
    }
    return rawUsage;
}

int64_t Database::GetUserLastMonthUsage(int userId) {
    int64_t upload = 0, download = 0;
    if (GetMonthlyTraffic(userId, Utils::GetLastMonth(), upload, download)) {
        return upload + download;
    }
    return 0;
}

int64_t Database::GetUserTotalUsage(int userId) {
    int64_t total = 0;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, 
            "SELECT SUM(upload_bytes), SUM(download_bytes) FROM traffic_records WHERE user_id = ?", 
            -1, &stmt, nullptr) == SQLITE_OK) {
            
            sqlite3_bind_int(stmt, 1, userId);
            
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                int64_t upload = sqlite3_column_int64(stmt, 0);
                int64_t download = sqlite3_column_int64(stmt, 1);
                total = upload + download;
            }
            sqlite3_finalize(stmt);
        }
    }
    
    int64_t unpersistedUpload = 0, unpersistedDownload = 0;
    TrafficMonitor::Instance().GetUserUnpersistedTraffic(userId, unpersistedUpload, unpersistedDownload);
    total += (unpersistedUpload + unpersistedDownload);
    
    return total;
}

bool Database::GetTotalTraffic(int64_t& upload, int64_t& download) {
    upload = 0;
    download = 0;
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_) return false;

    // 优先从 port_traffic_records 汇总全局物理流量
    sqlite3_stmt* stmt = nullptr;
    const char* sqlPort = "SELECT COALESCE(SUM(upload_bytes), 0), COALESCE(SUM(download_bytes), 0) FROM port_traffic_records;";
    if (sqlite3_prepare_v2(db_, sqlPort, -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            upload = sqlite3_column_int64(stmt, 0);
            download = sqlite3_column_int64(stmt, 1);
        }
        sqlite3_finalize(stmt);
    }

    // 若无节点流量记录，从用户 traffic_records 汇总
    if (upload == 0 && download == 0) {
        stmt = nullptr;
        const char* sqlUser = "SELECT COALESCE(SUM(upload_bytes), 0), COALESCE(SUM(download_bytes), 0) FROM traffic_records;";
        if (sqlite3_prepare_v2(db_, sqlUser, -1, &stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                upload = sqlite3_column_int64(stmt, 0);
                download = sqlite3_column_int64(stmt, 1);
            }
            sqlite3_finalize(stmt);
        }
    }
    return true;
}

bool Database::ResetUserTraffic(int userId) {
    // 1. 先将内存中未持久化的流量写入数据库，避免死锁并保证基准偏移精准
    TrafficMonitor::Instance().PersistTraffic();

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_) return false;

    std::string currentMonth = Utils::GetCurrentMonth();
    std::string currentDate = Utils::GetCurrentDate();

    // 2. 统计当前月份实际已发生流量（包括刚刚刷入的流量）
    int64_t monthlyRaw = 0;
    {
        std::string pattern = currentMonth + "%";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, 
            "SELECT COALESCE(SUM(upload_bytes), 0), COALESCE(SUM(download_bytes), 0) FROM traffic_records WHERE user_id = ? AND date LIKE ?", 
            -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, userId);
            sqlite3_bind_text(stmt, 2, pattern.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                monthlyRaw = sqlite3_column_int64(stmt, 0) + sqlite3_column_int64(stmt, 1);
            }
            sqlite3_finalize(stmt);
        }
    }

    // 3. 统计当前日期实际已发生流量（包括刚刚刷入的流量）
    int64_t dailyRaw = 0;
    {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, 
            "SELECT COALESCE(upload_bytes, 0), COALESCE(download_bytes, 0) FROM traffic_records WHERE user_id = ? AND date = ?", 
            -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, userId);
            sqlite3_bind_text(stmt, 2, currentDate.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                dailyRaw = sqlite3_column_int64(stmt, 0) + sqlite3_column_int64(stmt, 1);
            }
            sqlite3_finalize(stmt);
        }
    }

    // 4. 更新用户的配额重置基准偏移量，使当期已用额度归零并解除封禁
    // 重要说明：绝不删除 traffic_records，用户的总累计用量与30天趋势图等历史数据均完整保留！
    const char* sql = "UPDATE users SET quota_reset_month = ?, quota_offset_bytes = ?, "
                      "quota_reset_date = ?, daily_quota_offset_bytes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    sqlite3_bind_text(stmt, 1, currentMonth.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, monthlyRaw);
    sqlite3_bind_text(stmt, 3, currentDate.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, dailyRaw);
    sqlite3_bind_int(stmt, 5, userId);

    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);

    return success;
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

// 系统配置管理
bool Database::SetConfig(const std::string& key, const std::string& value) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    const char* sql = R"(
        INSERT INTO system_config (key, value, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(key) DO UPDATE SET
            value = excluded.value,
            updated_at = CURRENT_TIMESTAMP;
    )";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, value.c_str(), -1, SQLITE_TRANSIENT);
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

std::string Database::GetConfig(const std::string& key, const std::string& defaultValue) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, "SELECT value FROM system_config WHERE key = ?", -1, &stmt, nullptr) != SQLITE_OK) {
        return defaultValue;
    }
    
    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
    
    std::string result = defaultValue;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        result = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    }
    
    sqlite3_finalize(stmt);
    return result;
}

// 优先级调整（支持按分组独立调整顺序）
bool Database::MoveProxyPortUp(int portId, const std::string& groupName) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto allPorts = GetAllProxyPorts();
    if (groupName.empty()) {
        int targetIdx = -1;
        for (size_t i = 0; i < allPorts.size(); ++i) {
            if (allPorts[i].id == portId) {
                targetIdx = (int)i;
                break;
            }
        }
        if (targetIdx <= 0) return false;

        std::swap(allPorts[targetIdx], allPorts[targetIdx - 1]);
        for (size_t i = 0; i < allPorts.size(); ++i) {
            int newPriority = (int)(i + 1);
            std::string sql = "UPDATE proxy_ports SET priority = " + std::to_string(newPriority) + " WHERE id = " + std::to_string(allPorts[i].id) + ";";
            ExecuteSQL(sql);
        }
        return true;
    } else {
        std::vector<int> groupIndices;
        int targetInGroup = -1;
        for (size_t i = 0; i < allPorts.size(); ++i) {
            if (allPorts[i].groupName == groupName) {
                if (allPorts[i].id == portId) {
                    targetInGroup = (int)groupIndices.size();
                }
                groupIndices.push_back((int)i);
            }
        }
        if (targetInGroup <= 0) return false;

        int idxA = groupIndices[targetInGroup];
        int idxB = groupIndices[targetInGroup - 1];
        std::swap(allPorts[idxA], allPorts[idxB]);
        for (size_t i = 0; i < allPorts.size(); ++i) {
            int newPriority = (int)(i + 1);
            std::string sql = "UPDATE proxy_ports SET priority = " + std::to_string(newPriority) + " WHERE id = " + std::to_string(allPorts[i].id) + ";";
            ExecuteSQL(sql);
        }
        return true;
    }
}

bool Database::MoveProxyPortDown(int portId, const std::string& groupName) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto allPorts = GetAllProxyPorts();
    if (groupName.empty()) {
        int targetIdx = -1;
        for (size_t i = 0; i < allPorts.size(); ++i) {
            if (allPorts[i].id == portId) {
                targetIdx = (int)i;
                break;
            }
        }
        if (targetIdx < 0 || targetIdx >= (int)allPorts.size() - 1) return false;

        std::swap(allPorts[targetIdx], allPorts[targetIdx + 1]);
        for (size_t i = 0; i < allPorts.size(); ++i) {
            int newPriority = (int)(i + 1);
            std::string sql = "UPDATE proxy_ports SET priority = " + std::to_string(newPriority) + " WHERE id = " + std::to_string(allPorts[i].id) + ";";
            ExecuteSQL(sql);
        }
        return true;
    } else {
        std::vector<int> groupIndices;
        int targetInGroup = -1;
        for (size_t i = 0; i < allPorts.size(); ++i) {
            if (allPorts[i].groupName == groupName) {
                if (allPorts[i].id == portId) {
                    targetInGroup = (int)groupIndices.size();
                }
                groupIndices.push_back((int)i);
            }
        }
        if (targetInGroup < 0 || targetInGroup >= (int)groupIndices.size() - 1) return false;

        int idxA = groupIndices[targetInGroup];
        int idxB = groupIndices[targetInGroup + 1];
        std::swap(allPorts[idxA], allPorts[idxB]);
        for (size_t i = 0; i < allPorts.size(); ++i) {
            int newPriority = (int)(i + 1);
            std::string sql = "UPDATE proxy_ports SET priority = " + std::to_string(newPriority) + " WHERE id = " + std::to_string(allPorts[i].id) + ";";
            ExecuteSQL(sql);
        }
        return true;
    }
}

std::vector<std::string> Database::GetAllPortGroups() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<std::string> groups;
    if (!db_) return groups;
    std::set<std::string> seen;
    
    // 只获取当前实际存在有效节点的代理分组（排除智能路由 auto 端口）
    const char* sql = "SELECT DISTINCT group_name FROM proxy_ports "
                      "WHERE group_name IS NOT NULL AND group_name != '' "
                      "AND (upstream_type IS NULL OR upstream_type != 'auto') "
                      "ORDER BY group_name ASC";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* g = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            if (g && strlen(g) > 0) {
                groups.push_back(g);
                seen.insert(g);
            }
        }
        sqlite3_finalize(stmt);
    }
    
    // 若存在未明确指定分组名称（或为默认）的有效出站节点，且未包含默认分组，则补充默认分组
    const char* checkDefaultSql = "SELECT 1 FROM proxy_ports "
                                  "WHERE (group_name IS NULL OR group_name = '' OR group_name = '默认' OR group_name = '默认分组') "
                                  "AND (upstream_type IS NULL OR upstream_type != 'auto') LIMIT 1";
    if (sqlite3_prepare_v2(db_, checkDefaultSql, -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            if (seen.find("默认") == seen.end() && seen.find("默认分组") == seen.end()) {
                groups.push_back("默认");
                seen.insert("默认");
            }
        }
        sqlite3_finalize(stmt);
    }
    
    return groups;
}

bool Database::RenamePortGroup(const std::string& oldName, const std::string& newName) {
    if (oldName.empty() || newName.empty() || oldName == newName) return false;
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!db_) return false;

    // 1. 更新 proxy_ports 中的 group_name
    {
        sqlite3_stmt* stmt = nullptr;
        bool isDefault = (oldName == "默认" || oldName == "默认分组");
        const char* sql = isDefault
            ? "UPDATE proxy_ports SET group_name = ? WHERE group_name = ? OR group_name = '默认分组' OR group_name = '默认' OR group_name IS NULL OR group_name = ''"
            : "UPDATE proxy_ports SET group_name = ? WHERE group_name = ?";
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, newName.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, oldName.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }

    // 2. 更新 routing_rules 中的 target_group，保持分流规则同步生效
    {
        sqlite3_stmt* stmt = nullptr;
        bool isDefault = (oldName == "默认" || oldName == "默认分组");
        const char* sql = isDefault
            ? "UPDATE routing_rules SET target_group = ? WHERE target_group = ? OR target_group = '默认分组' OR target_group = '默认'"
            : "UPDATE routing_rules SET target_group = ? WHERE target_group = ?";
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, newName.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, oldName.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }

    return true;
}

void Database::EnsureFallbackRule() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
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
            ExecuteSQL(delSql);
        }
    } else if (fallbackIds.empty()) {
        // 尝试检查是否有原先手动添加的匹配所有流量的规则
        int existingId = 0;
        if (sqlite3_prepare_v2(db_, "SELECT id FROM routing_rules WHERE match_type = 'all' OR match_value = '*' LIMIT 1", -1, &stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                existingId = sqlite3_column_int(stmt, 0);
            }
            sqlite3_finalize(stmt);
        }
        
        if (existingId > 0) {
            ExecuteSQL("UPDATE routing_rules SET is_fallback = 1, match_type = 'all', match_value = '*' WHERE id = " + std::to_string(existingId) + ";");
        } else {
            // 获取当前普通规则的最大优先级
            int maxPrio = 0;
            if (sqlite3_prepare_v2(db_, "SELECT COALESCE(MAX(priority), 0) FROM routing_rules", -1, &stmt, nullptr) == SQLITE_OK) {
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    maxPrio = sqlite3_column_int(stmt, 0);
                }
                sqlite3_finalize(stmt);
            }
            // 插入一条默认兜底规则（未匹配时直连）
            const char* insertSql = R"(
                INSERT INTO routing_rules (priority, match_type, match_value, proxy_id, enabled, description, target_group, is_fallback)
                VALUES (?, 'all', '*', 0, 1, '默认兜底规则', '', 1);
            )";
            if (sqlite3_prepare_v2(db_, insertSql, -1, &stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, maxPrio + 1);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        }
    }
    
    // 确保默认兜底规则始终排在所有普通规则的最末尾
    int maxRegularPrio = 0;
    if (sqlite3_prepare_v2(db_, "SELECT COALESCE(MAX(priority), 0) FROM routing_rules WHERE is_fallback = 0", -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            maxRegularPrio = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    int fallbackPrio = (maxRegularPrio >= 999999) ? (maxRegularPrio + 1) : 999999;
    ExecuteSQL("UPDATE routing_rules SET priority = " + std::to_string(fallbackPrio) + " WHERE is_fallback = 1;");
}

// 路由规则管理
bool Database::AddRoutingRule(const RoutingRule& rule) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    if (rule.isFallback) {
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
            return UpdateRoutingRule(rCopy);
        }
    }
    
    // 新添加的分流规则应为最后一条（排在所有普通规则的末尾，默认兜底规则之前）
    int maxRegularPriority = 0;
    sqlite3_stmt* stmtPrio = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT COALESCE(MAX(priority), 0) FROM routing_rules WHERE is_fallback = 0", -1, &stmtPrio, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmtPrio) == SQLITE_ROW) {
            maxRegularPriority = sqlite3_column_int(stmtPrio, 0);
        }
        sqlite3_finalize(stmtPrio);
    }
    int newPriority = maxRegularPriority + 1;
    
    const char* sql = R"(
        INSERT INTO routing_rules (priority, match_type, match_value, proxy_id, enabled, description, target_group, is_fallback)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?);
    )";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, newPriority);
    sqlite3_bind_text(stmt, 2, rule.matchType.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, rule.matchValue.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, rule.proxyId);
    sqlite3_bind_int(stmt, 5, rule.enabled ? 1 : 0);
    sqlite3_bind_text(stmt, 6, rule.description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, rule.targetGroup.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 8, rule.isFallback ? 1 : 0);
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    
    if (success) {
        // 确保默认兜底规则始终紧随在所有规则的最末端
        int fallbackPrio = (newPriority >= 999999) ? (newPriority + 1) : 999999;
        ExecuteSQL("UPDATE routing_rules SET priority = " + std::to_string(fallbackPrio) + " WHERE is_fallback = 1;");
    }
    return success;
}

bool Database::UpdateRoutingRule(const RoutingRule& rule) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    const char* sql = R"(
        UPDATE routing_rules SET 
            match_type = ?, match_value = ?, proxy_id = ?, enabled = ?, description = ?, target_group = ?, is_fallback = ?
        WHERE id = ?;
    )";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, rule.matchType.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, rule.matchValue.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, rule.proxyId);
    sqlite3_bind_int(stmt, 4, rule.enabled ? 1 : 0);
    sqlite3_bind_text(stmt, 5, rule.description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, rule.targetGroup.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 7, rule.isFallback ? 1 : 0);
    sqlite3_bind_int(stmt, 8, rule.id);
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::DeleteRoutingRule(int ruleId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    RoutingRule existing;
    if (GetRoutingRule(ruleId, existing) && existing.isFallback) {
        Utils::Log("Cannot delete default fallback routing rule");
        return false;
    }
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, "DELETE FROM routing_rules WHERE id = ?", -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, ruleId);
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    
    if (success) {
        // 重新规范优先级，保证连续并保持兜底规则在末尾
        auto rules = GetAllRoutingRules();
        int prio = 1;
        for (const auto& r : rules) {
            if (!r.isFallback) {
                ExecuteSQL("UPDATE routing_rules SET priority = " + std::to_string(prio++) + " WHERE id = " + std::to_string(r.id) + ";");
            }
        }
        ExecuteSQL("UPDATE routing_rules SET priority = " + std::to_string(prio) + " WHERE is_fallback = 1;");
    }
    return success;
}

bool Database::GetRoutingRule(int ruleId, RoutingRule& rule) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT id, priority, match_type, match_value, proxy_id, enabled, description, created_at, target_group, is_fallback FROM routing_rules WHERE id = ?";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, ruleId);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        rule.id = sqlite3_column_int(stmt, 0);
        rule.priority = sqlite3_column_int(stmt, 1);
        const char* mType = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        rule.matchType = mType ? mType : "";
        const char* mVal = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        rule.matchValue = mVal ? mVal : "";
        rule.proxyId = sqlite3_column_int(stmt, 4);
        rule.enabled = sqlite3_column_int(stmt, 5) != 0;
        const char* desc = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        rule.description = desc ? desc : "";
        const char* created = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        rule.createdAt = created ? created : "";
        const char* grp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
        rule.targetGroup = grp ? grp : "";
        rule.isFallback = sqlite3_column_int(stmt, 9) != 0;
        sqlite3_finalize(stmt);
        return true;
    }
    
    sqlite3_finalize(stmt);
    return false;
}

std::vector<RoutingRule> Database::GetAllRoutingRules() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<RoutingRule> rules;
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT id, priority, match_type, match_value, proxy_id, enabled, description, created_at, target_group, is_fallback FROM routing_rules ORDER BY is_fallback ASC, priority ASC";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return rules;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        RoutingRule rule;
        rule.id = sqlite3_column_int(stmt, 0);
        rule.priority = sqlite3_column_int(stmt, 1);
        const char* mType = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        rule.matchType = mType ? mType : "";
        const char* mVal = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        rule.matchValue = mVal ? mVal : "";
        rule.proxyId = sqlite3_column_int(stmt, 4);
        rule.enabled = sqlite3_column_int(stmt, 5) != 0;
        const char* desc = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        rule.description = desc ? desc : "";
        const char* created = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        rule.createdAt = created ? created : "";
        const char* grp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
        rule.targetGroup = grp ? grp : "";
        rule.isFallback = sqlite3_column_int(stmt, 9) != 0;
        rules.push_back(rule);
    }
    
    sqlite3_finalize(stmt);
    return rules;
}

std::vector<RoutingRule> Database::GetEnabledRoutingRules() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<RoutingRule> rules;
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT id, priority, match_type, match_value, proxy_id, enabled, description, created_at, target_group, is_fallback FROM routing_rules WHERE enabled = 1 ORDER BY is_fallback ASC, priority ASC";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return rules;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        RoutingRule rule;
        rule.id = sqlite3_column_int(stmt, 0);
        rule.priority = sqlite3_column_int(stmt, 1);
        const char* mType = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        rule.matchType = mType ? mType : "";
        const char* mVal = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        rule.matchValue = mVal ? mVal : "";
        rule.proxyId = sqlite3_column_int(stmt, 4);
        rule.enabled = true;
        const char* desc = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        rule.description = desc ? desc : "";
        const char* created = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        rule.createdAt = created ? created : "";
        const char* grp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
        rule.targetGroup = grp ? grp : "";
        rule.isFallback = sqlite3_column_int(stmt, 9) != 0;
        rules.push_back(rule);
    }
    
    sqlite3_finalize(stmt);
    return rules;
}

bool Database::MoveRoutingRuleUp(int ruleId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto rules = GetAllRoutingRules();
    int targetIdx = -1;
    for (size_t i = 0; i < rules.size(); ++i) {
        if (rules[i].id == ruleId) {
            targetIdx = (int)i;
            break;
        }
    }
    if (targetIdx <= 0 || rules[targetIdx].isFallback) return false;

    std::swap(rules[targetIdx], rules[targetIdx - 1]);
    int prio = 1;
    for (size_t i = 0; i < rules.size(); ++i) {
        if (!rules[i].isFallback) {
            std::string sql = "UPDATE routing_rules SET priority = " + std::to_string(prio++) + " WHERE id = " + std::to_string(rules[i].id) + ";";
            ExecuteSQL(sql);
        }
    }
    ExecuteSQL("UPDATE routing_rules SET priority = " + std::to_string(prio) + " WHERE is_fallback = 1;");
    return true;
}

bool Database::MoveRoutingRuleDown(int ruleId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto rules = GetAllRoutingRules();
    int targetIdx = -1;
    for (size_t i = 0; i < rules.size(); ++i) {
        if (rules[i].id == ruleId) {
            targetIdx = (int)i;
            break;
        }
    }
    if (targetIdx < 0 || targetIdx >= (int)rules.size() - 1 || rules[targetIdx].isFallback) return false;
    // 如果下一条是默认兜底规则，则不可下移越过兜底规则
    if (rules[targetIdx + 1].isFallback) return false;

    std::swap(rules[targetIdx], rules[targetIdx + 1]);
    int prio = 1;
    for (size_t i = 0; i < rules.size(); ++i) {
        if (!rules[i].isFallback) {
            std::string sql = "UPDATE routing_rules SET priority = " + std::to_string(prio++) + " WHERE id = " + std::to_string(rules[i].id) + ";";
            ExecuteSQL(sql);
        }
    }
    ExecuteSQL("UPDATE routing_rules SET priority = " + std::to_string(prio) + " WHERE is_fallback = 1;");
    return true;
}

// 流量统计持久化存储
bool Database::SavePortTrafficStats(int portId, int64_t upload1h, int64_t download1h,
                                    int64_t upload24h, int64_t download24h,
                                    int64_t uploadWeek, int64_t downloadWeek,
                                    int64_t uploadMonth, int64_t downloadMonth,
                                    int64_t uploadLastMonth, int64_t downloadLastMonth) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    const char* sql = R"(
        INSERT INTO port_traffic_stats (port_id, upload_1h, download_1h, upload_24h, download_24h,
                                        upload_week, download_week, upload_month, download_month,
                                        upload_last_month, download_last_month, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(port_id) DO UPDATE SET
            upload_1h = excluded.upload_1h,
            download_1h = excluded.download_1h,
            upload_24h = excluded.upload_24h,
            download_24h = excluded.download_24h,
            upload_week = excluded.upload_week,
            download_week = excluded.download_week,
            upload_month = excluded.upload_month,
            download_month = excluded.download_month,
            upload_last_month = excluded.upload_last_month,
            download_last_month = excluded.download_last_month,
            updated_at = CURRENT_TIMESTAMP;
    )";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, portId);
    sqlite3_bind_int64(stmt, 2, upload1h);
    sqlite3_bind_int64(stmt, 3, download1h);
    sqlite3_bind_int64(stmt, 4, upload24h);
    sqlite3_bind_int64(stmt, 5, download24h);
    sqlite3_bind_int64(stmt, 6, uploadWeek);
    sqlite3_bind_int64(stmt, 7, downloadWeek);
    sqlite3_bind_int64(stmt, 8, uploadMonth);
    sqlite3_bind_int64(stmt, 9, downloadMonth);
    sqlite3_bind_int64(stmt, 10, uploadLastMonth);
    sqlite3_bind_int64(stmt, 11, downloadLastMonth);
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::LoadPortTrafficStats(int portId, int64_t& upload1h, int64_t& download1h,
                                    int64_t& upload24h, int64_t& download24h,
                                    int64_t& uploadWeek, int64_t& downloadWeek,
                                    int64_t& uploadMonth, int64_t& downloadMonth,
                                    int64_t& uploadLastMonth, int64_t& downloadLastMonth) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, "SELECT upload_1h, download_1h, upload_24h, download_24h, upload_week, download_week, upload_month, download_month, upload_last_month, download_last_month FROM port_traffic_stats WHERE port_id = ?", -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, portId);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        upload1h = sqlite3_column_int64(stmt, 0);
        download1h = sqlite3_column_int64(stmt, 1);
        upload24h = sqlite3_column_int64(stmt, 2);
        download24h = sqlite3_column_int64(stmt, 3);
        uploadWeek = sqlite3_column_int64(stmt, 4);
        downloadWeek = sqlite3_column_int64(stmt, 5);
        uploadMonth = sqlite3_column_int64(stmt, 6);
        downloadMonth = sqlite3_column_int64(stmt, 7);
        uploadLastMonth = sqlite3_column_int64(stmt, 8);
        downloadLastMonth = sqlite3_column_int64(stmt, 9);
        sqlite3_finalize(stmt);
        return true;
    }
    
    sqlite3_finalize(stmt);
    return false;
}

bool Database::SaveUserTrafficStats(int userId, int64_t upload1h, int64_t download1h,
                                    int64_t upload24h, int64_t download24h,
                                    int64_t uploadWeek, int64_t downloadWeek,
                                    int64_t uploadMonth, int64_t downloadMonth,
                                    int64_t uploadLastMonth, int64_t downloadLastMonth) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    const char* sql = R"(
        INSERT INTO user_traffic_stats (user_id, upload_1h, download_1h, upload_24h, download_24h,
                                        upload_week, download_week, upload_month, download_month,
                                        upload_last_month, download_last_month, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(user_id) DO UPDATE SET
            upload_1h = excluded.upload_1h,
            download_1h = excluded.download_1h,
            upload_24h = excluded.upload_24h,
            download_24h = excluded.download_24h,
            upload_week = excluded.upload_week,
            download_week = excluded.download_week,
            upload_month = excluded.upload_month,
            download_month = excluded.download_month,
            upload_last_month = excluded.upload_last_month,
            download_last_month = excluded.download_last_month,
            updated_at = CURRENT_TIMESTAMP;
    )";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, userId);
    sqlite3_bind_int64(stmt, 2, upload1h);
    sqlite3_bind_int64(stmt, 3, download1h);
    sqlite3_bind_int64(stmt, 4, upload24h);
    sqlite3_bind_int64(stmt, 5, download24h);
    sqlite3_bind_int64(stmt, 6, uploadWeek);
    sqlite3_bind_int64(stmt, 7, downloadWeek);
    sqlite3_bind_int64(stmt, 8, uploadMonth);
    sqlite3_bind_int64(stmt, 9, downloadMonth);
    sqlite3_bind_int64(stmt, 10, uploadLastMonth);
    sqlite3_bind_int64(stmt, 11, downloadLastMonth);
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::LoadUserTrafficStats(int userId, int64_t& upload1h, int64_t& download1h,
                                    int64_t& upload24h, int64_t& download24h,
                                    int64_t& uploadWeek, int64_t& downloadWeek,
                                    int64_t& uploadMonth, int64_t& downloadMonth,
                                    int64_t& uploadLastMonth, int64_t& downloadLastMonth) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, "SELECT upload_1h, download_1h, upload_24h, download_24h, upload_week, download_week, upload_month, download_month, upload_last_month, download_last_month FROM user_traffic_stats WHERE user_id = ?", -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, userId);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        upload1h = sqlite3_column_int64(stmt, 0);
        download1h = sqlite3_column_int64(stmt, 1);
        upload24h = sqlite3_column_int64(stmt, 2);
        download24h = sqlite3_column_int64(stmt, 3);
        uploadWeek = sqlite3_column_int64(stmt, 4);
        downloadWeek = sqlite3_column_int64(stmt, 5);
        uploadMonth = sqlite3_column_int64(stmt, 6);
        downloadMonth = sqlite3_column_int64(stmt, 7);
        uploadLastMonth = sqlite3_column_int64(stmt, 8);
        downloadLastMonth = sqlite3_column_int64(stmt, 9);
        sqlite3_finalize(stmt);
        return true;
    }
    
    sqlite3_finalize(stmt);
    return false;
}


std::vector<int> Database::GetAllPortIds() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<int> ids;
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, "SELECT id FROM proxy_ports", -1, &stmt, nullptr) != SQLITE_OK) {
        return ids;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ids.push_back(sqlite3_column_int(stmt, 0));
    }
    
    sqlite3_finalize(stmt);
    return ids;
}

std::vector<int> Database::GetAllUserIds() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<int> ids;
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, "SELECT id FROM users", -1, &stmt, nullptr) != SQLITE_OK) {
        return ids;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ids.push_back(sqlite3_column_int(stmt, 0));
    }
    
    sqlite3_finalize(stmt);
    return ids;
}

bool Database::AddToWhitelist(const std::string& ip, const std::string& remark) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    const char* sql = "INSERT OR IGNORE INTO ip_whitelist (ip, remark) VALUES (?, ?)";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, remark.c_str(), -1, SQLITE_TRANSIENT);
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::UpdateWhitelist(int id, const std::string& ip, const std::string& remark) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    const char* sql = "UPDATE ip_whitelist SET ip = ?, remark = ? WHERE id = ?";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, remark.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, id);
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::RemoveFromWhitelist(int id) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    const char* sql = "DELETE FROM ip_whitelist WHERE id = ?";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_int(stmt, 1, id);
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

std::vector<Database::BanInfo> Database::GetWhitelist() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<BanInfo> list;
    const char* sql = "SELECT id, ip, remark, created_at FROM ip_whitelist ORDER BY id DESC";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return list;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        BanInfo info;
        info.id = sqlite3_column_int(stmt, 0);
        info.ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        info.remark = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        info.expiryTime = 0;
        info.createdAt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        list.push_back(info);
    }
    sqlite3_finalize(stmt);
    return list;
}

bool Database::IsWhitelisted(const std::string& ip) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    // 为了效率，先尝试精确匹配
    const char* sql = "SELECT 1 FROM ip_whitelist WHERE ip = ?";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            sqlite3_finalize(stmt);
            return true;
        }
        sqlite3_finalize(stmt);
    }

    // 再尝试 CIDR 匹配
    auto whitelist = GetWhitelist();
    for (const auto& item : whitelist) {
        if (item.ip.find('/') != std::string::npos || item.ip.find('*') != std::string::npos) {
            if (Utils::IsIPAllowed(ip, item.ip)) return true;
        }
    }
    return false;
}

bool Database::AddToBlacklist(const std::string& ip, const std::string& remark) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    const char* sql = "INSERT OR IGNORE INTO ip_blacklist (ip, remark) VALUES (?, ?)";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, remark.c_str(), -1, SQLITE_TRANSIENT);
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::UpdateBlacklist(int id, const std::string& ip, const std::string& remark) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    const char* sql = "UPDATE ip_blacklist SET ip = ?, remark = ? WHERE id = ?";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, remark.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, id);
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::RemoveFromBlacklist(int id) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    const char* sql = "DELETE FROM ip_blacklist WHERE id = ?";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_int(stmt, 1, id);
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::RemoveBlacklistByIP(const std::string& ip) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    const char* sql = "DELETE FROM ip_blacklist WHERE ip = ?";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_TRANSIENT);
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

std::vector<Database::BanInfo> Database::GetBlacklist() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<BanInfo> list;
    const char* sql = "SELECT id, ip, remark, created_at FROM ip_blacklist ORDER BY id DESC";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return list;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        BanInfo info;
        info.id = sqlite3_column_int(stmt, 0);
        info.ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        info.remark = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        info.expiryTime = 0;
        info.createdAt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        list.push_back(info);
    }
    sqlite3_finalize(stmt);
    return list;
}

bool Database::IsBlacklisted(const std::string& ip) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    // 精确匹配
    const char* sql = "SELECT 1 FROM ip_blacklist WHERE ip = ?";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            sqlite3_finalize(stmt);
            return true;
        }
        sqlite3_finalize(stmt);
    }

    // CIDR 匹配
    auto blacklist = GetBlacklist();
    for (const auto& item : blacklist) {
        if (item.ip.find('/') != std::string::npos || item.ip.find('*') != std::string::npos) {
            if (Utils::IsIPAllowed(ip, item.ip)) return true;
        }
    }
    return false;
}

bool Database::AddToAutoBan(const std::string& ip, int64_t expiryTime) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    const char* sql = "INSERT OR REPLACE INTO auto_ban_list (ip, expiry_time) VALUES (?, ?)";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, expiryTime);
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::RemoveFromAutoBan(int id) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    const char* sql = "DELETE FROM auto_ban_list WHERE id = ?";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_int(stmt, 1, id);
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::RemoveAutoBanByIP(const std::string& ip) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    const char* sql = "DELETE FROM auto_ban_list WHERE ip = ?";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_TRANSIENT);
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::ClearAllAutoBans() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    ExecuteSQL("DELETE FROM login_failures;");
    return ExecuteSQL("DELETE FROM auto_ban_list;");
}

std::vector<Database::BanInfo> Database::GetAutoBanList() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<BanInfo> list;
    const char* sql = "SELECT id, ip, expiry_time, created_at FROM auto_ban_list ORDER BY expiry_time ASC";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return list;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        BanInfo info;
        info.id = sqlite3_column_int(stmt, 0);
        info.ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        info.remark = ""; // Auto ban has no remark
        info.expiryTime = sqlite3_column_int64(stmt, 2);
        info.createdAt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        list.push_back(info);
    }
    sqlite3_finalize(stmt);
    return list;
}

bool Database::IsAutoBanned(const std::string& ip) {
    CleanExpiredAutoBans();
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    const char* sql = "SELECT 1 FROM auto_ban_list WHERE ip = ? AND expiry_time > ?";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, time(nullptr));
    bool found = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return found;
}

void Database::CleanExpiredAutoBans() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    const char* sql = "DELETE FROM auto_ban_list WHERE expiry_time <= ?";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, time(nullptr));
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
}

bool Database::AddToNoAuthList(const std::string& ip, const std::string& remark) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    const char* sql = "INSERT OR IGNORE INTO ip_no_auth (ip, remark) VALUES (?, ?)";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, remark.c_str(), -1, SQLITE_TRANSIENT);
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::UpdateNoAuthList(int id, const std::string& ip, const std::string& remark) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    const char* sql = "UPDATE ip_no_auth SET ip = ?, remark = ? WHERE id = ?";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, remark.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, id);
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::RemoveFromNoAuthList(int id) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    const char* sql = "DELETE FROM ip_no_auth WHERE id = ?";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_int(stmt, 1, id);
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

std::vector<Database::BanInfo> Database::GetNoAuthList() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<BanInfo> list;
    const char* sql = "SELECT id, ip, remark, created_at FROM ip_no_auth ORDER BY id DESC";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return list;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        BanInfo info;
        info.id = sqlite3_column_int(stmt, 0);
        info.ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        info.remark = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        info.expiryTime = 0;
        info.createdAt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        list.push_back(info);
    }
    sqlite3_finalize(stmt);
    return list;
}

bool Database::IsNoAuthIP(const std::string& ip) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    // 精确匹配
    const char* sql = "SELECT 1 FROM ip_no_auth WHERE ip = ?";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            sqlite3_finalize(stmt);
            return true;
        }
        sqlite3_finalize(stmt);
    }

    // CIDR 匹配
    auto noAuthList = GetNoAuthList();
    for (const auto& item : noAuthList) {
        if (item.ip.find('/') != std::string::npos || item.ip.find('*') != std::string::npos) {
            if (Utils::IsIPAllowed(ip, item.ip)) return true;
        }
    }
    return false;
}

bool Database::RecordLoginFailure(const std::string& ip) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    const char* sql = "INSERT INTO login_failures (ip, fail_time) VALUES (?, ?)";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, time(nullptr));
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

int Database::GetLoginFailures(const std::string& ip, int minutes) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    const char* sql = "SELECT COUNT(*) FROM login_failures WHERE ip = ? AND fail_time > ?";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return 0;
    
    int64_t threshold = time(nullptr) - (minutes * 60);
    sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, threshold);
    
    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return count;
}

void Database::CleanOldLoginFailures(int minutes) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    const char* sql = "DELETE FROM login_failures WHERE fail_time <= ?";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        int64_t threshold = time(nullptr) - (minutes * 60);
        sqlite3_bind_int64(stmt, 1, threshold);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
}

// Clash 订阅管理
bool Database::AddSubscription(const ClashSubscription& sub) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    const char* sql = R"(
        INSERT INTO clash_subscriptions (name, url, raw_content, update_interval_days, update_time, last_updated, upload_bytes, download_bytes, total_bytes, expire_time, website_url, include_filter, exclude_filter, reset_cycle_days, reset_start_date, cycle_offset_bytes, last_reset_cycle)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    )";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, sub.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, sub.url.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, sub.rawContent.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, sub.updateIntervalDays);
    sqlite3_bind_text(stmt, 5, sub.updateTime.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, sub.lastUpdated.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 7, sub.uploadBytes);
    sqlite3_bind_int64(stmt, 8, sub.downloadBytes);
    sqlite3_bind_int64(stmt, 9, sub.totalBytes);
    sqlite3_bind_text(stmt, 10, sub.expireTime.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 11, sub.websiteUrl.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 12, sub.includeFilter.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 13, sub.excludeFilter.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 14, sub.resetCycleDays);
    sqlite3_bind_text(stmt, 15, sub.resetStartDate.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 16, sub.cycleOffsetBytes);
    sqlite3_bind_int(stmt, 17, sub.lastResetCycle);
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::UpdateSubscription(const ClashSubscription& sub) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    const char* sql = R"(
        UPDATE clash_subscriptions SET 
            name = ?, url = ?, raw_content = ?, update_interval_days = ?, 
            update_time = ?, last_updated = ?, upload_bytes = ?, download_bytes = ?, 
            total_bytes = ?, expire_time = ?, website_url = ?, include_filter = ?, exclude_filter = ?,
            reset_cycle_days = ?, reset_start_date = ?, cycle_offset_bytes = ?, last_reset_cycle = ?
        WHERE id = ?;
    )";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, sub.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, sub.url.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, sub.rawContent.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, sub.updateIntervalDays);
    sqlite3_bind_text(stmt, 5, sub.updateTime.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, sub.lastUpdated.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 7, sub.uploadBytes);
    sqlite3_bind_int64(stmt, 8, sub.downloadBytes);
    sqlite3_bind_int64(stmt, 9, sub.totalBytes);
    sqlite3_bind_text(stmt, 10, sub.expireTime.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 11, sub.websiteUrl.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 12, sub.includeFilter.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 13, sub.excludeFilter.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 14, sub.resetCycleDays);
    sqlite3_bind_text(stmt, 15, sub.resetStartDate.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 16, sub.cycleOffsetBytes);
    sqlite3_bind_int(stmt, 17, sub.lastResetCycle);
    sqlite3_bind_int(stmt, 18, sub.id);
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::DeleteSubscription(int subId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, "DELETE FROM clash_subscriptions WHERE id = ?", -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, subId);
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::GetSubscription(int subId, ClashSubscription& sub) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT id, name, url, raw_content, update_interval_days, update_time, last_updated, created_at, upload_bytes, download_bytes, total_bytes, expire_time, website_url, include_filter, exclude_filter, reset_cycle_days, reset_start_date, cycle_offset_bytes, last_reset_cycle FROM clash_subscriptions WHERE id = ?";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, subId);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        sub.id = sqlite3_column_int(stmt, 0);
        const char* name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        sub.name = name ? name : "";
        const char* url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        sub.url = url ? url : "";
        const char* raw = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        sub.rawContent = raw ? raw : "";
        sub.updateIntervalDays = sqlite3_column_int(stmt, 4);
        const char* utime = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        sub.updateTime = utime ? utime : "04:00";
        const char* last = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        sub.lastUpdated = last ? last : "";
        const char* created = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        sub.createdAt = created ? created : "";
        sub.uploadBytes = sqlite3_column_int64(stmt, 8);
        sub.downloadBytes = sqlite3_column_int64(stmt, 9);
        sub.totalBytes = sqlite3_column_int64(stmt, 10);
        const char* exp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));
        sub.expireTime = exp ? exp : "";
        const char* web = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 12));
        sub.websiteUrl = web ? web : "";
        const char* inc = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 13));
        sub.includeFilter = inc ? inc : "";
        const char* exc = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 14));
        sub.excludeFilter = exc ? exc : "";
        sub.resetCycleDays = sqlite3_column_int(stmt, 15);
        if (sub.resetCycleDays < 0) sub.resetCycleDays = 0;
        const char* rsd = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 16));
        sub.resetStartDate = rsd ? rsd : "";
        sub.cycleOffsetBytes = sqlite3_column_int64(stmt, 17);
        sub.lastResetCycle = sqlite3_column_int(stmt, 18);
        sqlite3_finalize(stmt);
        return true;
    }
    
    sqlite3_finalize(stmt);
    return false;
}

std::vector<ClashSubscription> Database::GetAllSubscriptions() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<ClashSubscription> subs;
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT id, name, url, raw_content, update_interval_days, update_time, last_updated, created_at, upload_bytes, download_bytes, total_bytes, expire_time, website_url, include_filter, exclude_filter, reset_cycle_days, reset_start_date, cycle_offset_bytes, last_reset_cycle FROM clash_subscriptions ORDER BY id ASC";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return subs;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ClashSubscription sub;
        sub.id = sqlite3_column_int(stmt, 0);
        const char* name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        sub.name = name ? name : "";
        const char* url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        sub.url = url ? url : "";
        const char* raw = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        sub.rawContent = raw ? raw : "";
        sub.updateIntervalDays = sqlite3_column_int(stmt, 4);
        const char* utime = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        sub.updateTime = utime ? utime : "04:00";
        const char* last = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        sub.lastUpdated = last ? last : "";
        const char* created = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        sub.createdAt = created ? created : "";
        sub.uploadBytes = sqlite3_column_int64(stmt, 8);
        sub.downloadBytes = sqlite3_column_int64(stmt, 9);
        sub.totalBytes = sqlite3_column_int64(stmt, 10);
        const char* exp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));
        sub.expireTime = exp ? exp : "";
        const char* web = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 12));
        sub.websiteUrl = web ? web : "";
        const char* inc = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 13));
        sub.includeFilter = inc ? inc : "";
        const char* exc = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 14));
        sub.excludeFilter = exc ? exc : "";
        sub.resetCycleDays = sqlite3_column_int(stmt, 15);
        if (sub.resetCycleDays < 0) sub.resetCycleDays = 0;
        const char* rsd = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 16));
        sub.resetStartDate = rsd ? rsd : "";
        sub.cycleOffsetBytes = sqlite3_column_int64(stmt, 17);
        sub.lastResetCycle = sqlite3_column_int(stmt, 18);
        subs.push_back(sub);
    }
    
    sqlite3_finalize(stmt);
    return subs;
}

std::vector<ProxyPort> Database::GetPortsBySubscriptionId(int subId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<ProxyPort> ports;
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT id, listen_port, upstream_type, upstream_host, upstream_port, upstream_user, upstream_pass, enabled, description, priority, created_at, xray_config, clash_config, clash_subscription_id, clash_node_name, auto_check, allowed_targets, group_name FROM proxy_ports WHERE clash_subscription_id = ? ORDER BY priority ASC";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return ports;
    }
    
    sqlite3_bind_int(stmt, 1, subId);
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ProxyPort port;
        port.id = sqlite3_column_int(stmt, 0);
        port.listenPort = sqlite3_column_int(stmt, 1);
        const char* type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        port.upstreamType = type ? type : "";
        const char* host = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        port.upstreamHost = host ? host : "";
        port.upstreamPort = sqlite3_column_int(stmt, 4);
        const char* user = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        port.upstreamUser = user ? user : "";
        const char* pass = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        port.upstreamPass = pass ? pass : "";
        port.enabled = sqlite3_column_int(stmt, 7) != 0;
        const char* desc = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
        port.description = desc ? desc : "";
        port.priority = sqlite3_column_int(stmt, 9);
        const char* created = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
        port.createdAt = created ? created : "";
        const char* xrayConf = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));
        port.xrayConfig = xrayConf ? xrayConf : "";
        const char* clashConf = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 12));
        port.clashConfig = clashConf ? clashConf : "";
        port.clashSubscriptionId = sqlite3_column_int(stmt, 13);
        const char* nodeName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 14));
        port.clashNodeName = nodeName ? nodeName : "";
        port.autoCheck = sqlite3_column_int(stmt, 15) != 0;
        const char* allowedTgts = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 16));
        port.allowedTargets = allowedTgts ? allowedTgts : "*";
        const char* grp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 17));
        port.groupName = grp ? grp : "";
        if (port.groupName.empty()) {
            port.groupName = InferNodeGroup(port.clashNodeName, port.description);
        }
        ports.push_back(port);
    }
    
    sqlite3_finalize(stmt);
    return ports;
}

bool Database::DeletePortsBySubscriptionId(int subId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, "DELETE FROM proxy_ports WHERE clash_subscription_id = ?", -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, subId);
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
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
        DeleteProxyPort(dupId);
    }
    return (int)duplicateIds.size();
}

// 应用代理规则管理
bool Database::AddAppProxyRule(const AppProxyRule& rule) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    const char* sql = R"(
        INSERT INTO app_proxy_rules (app_name, proxy_id, priority, enabled, description)
        VALUES (?, ?, ?, ?, ?);
    )";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, rule.appName.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, rule.proxyId);
    sqlite3_bind_int(stmt, 3, rule.priority);
    sqlite3_bind_int(stmt, 4, rule.enabled ? 1 : 0);
    sqlite3_bind_text(stmt, 5, rule.description.c_str(), -1, SQLITE_TRANSIENT);
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::UpdateAppProxyRule(const AppProxyRule& rule) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    const char* sql = R"(
        UPDATE app_proxy_rules SET 
            app_name = ?, proxy_id = ?, priority = ?, enabled = ?, description = ?
        WHERE id = ?;
    )";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, rule.appName.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, rule.proxyId);
    sqlite3_bind_int(stmt, 3, rule.priority);
    sqlite3_bind_int(stmt, 4, rule.enabled ? 1 : 0);
    sqlite3_bind_text(stmt, 5, rule.description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 6, rule.id);
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::DeleteAppProxyRule(int ruleId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, "DELETE FROM app_proxy_rules WHERE id = ?", -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, ruleId);
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::GetAppProxyRule(int ruleId, AppProxyRule& rule) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT id, app_name, proxy_id, priority, enabled, description, created_at FROM app_proxy_rules WHERE id = ?";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, ruleId);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        rule.id = sqlite3_column_int(stmt, 0);
        rule.appName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        rule.proxyId = sqlite3_column_int(stmt, 2);
        rule.priority = sqlite3_column_int(stmt, 3);
        rule.enabled = sqlite3_column_int(stmt, 4) != 0;
        const char* desc = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        rule.description = desc ? desc : "";
        const char* created = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        rule.createdAt = created ? created : "";
        sqlite3_finalize(stmt);
        return true;
    }
    
    sqlite3_finalize(stmt);
    return false;
}

std::vector<Database::AppProxyRule> Database::GetAllAppProxyRules() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<AppProxyRule> rules;
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT id, app_name, proxy_id, priority, enabled, description, created_at FROM app_proxy_rules ORDER BY priority ASC, id ASC";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return rules;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        AppProxyRule rule;
        rule.id = sqlite3_column_int(stmt, 0);
        rule.appName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        rule.proxyId = sqlite3_column_int(stmt, 2);
        rule.priority = sqlite3_column_int(stmt, 3);
        rule.enabled = sqlite3_column_int(stmt, 4) != 0;
        const char* desc = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        rule.description = desc ? desc : "";
        const char* created = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        rule.createdAt = created ? created : "";
        rules.push_back(rule);
    }
    
    sqlite3_finalize(stmt);
    return rules;
}

std::vector<Database::AppProxyRule> Database::GetEnabledAppProxyRules() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<AppProxyRule> rules;
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT id, app_name, proxy_id, priority, enabled, description, created_at FROM app_proxy_rules WHERE enabled = 1 ORDER BY priority ASC, id ASC";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return rules;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        AppProxyRule rule;
        rule.id = sqlite3_column_int(stmt, 0);
        rule.appName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        rule.proxyId = sqlite3_column_int(stmt, 2);
        rule.priority = sqlite3_column_int(stmt, 3);
        rule.enabled = sqlite3_column_int(stmt, 4) != 0;
        const char* desc = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        rule.description = desc ? desc : "";
        const char* created = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        rule.createdAt = created ? created : "";
        rules.push_back(rule);
    }
    
    sqlite3_finalize(stmt);
    return rules;
}

nlohmann::json Database::ExportConfig() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    nlohmann::json root;
    root["format"] = "ProxyRelayConfig";
    root["version"] = "1.0";
    root["platform"] = "windows";
    root["export_time"] = Utils::FormatTime(std::time(nullptr));
    
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
        blackArr.push_back({ {"ip", b.ip}, {"remark", b.remark} });
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

    ExecuteSQL("BEGIN TRANSACTION;");

    try {
        if (overwrite) {
            ExecuteSQL("DELETE FROM routing_rules;");
            ExecuteSQL("DELETE FROM proxy_ports;");
            ExecuteSQL("DELETE FROM clash_subscriptions;");
            ExecuteSQL("DELETE FROM users;");
            ExecuteSQL("DELETE FROM ip_whitelist;");
            ExecuteSQL("DELETE FROM ip_blacklist;");
            ExecuteSQL("DELETE FROM ip_no_auth;");
        }

        // 1. Clash 订阅 (先导入以便端口关联正确的 SubscriptionId)
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
                            UpdateSubscription(s);
                            oldSubIdToNewSubId[oldId] = existing.id;
                            exists = true;
                            break;
                        }
                    }
                }
                if (!exists) {
                    AddSubscription(s);
                    int newSubId = (int)sqlite3_last_insert_rowid(db_);
                    oldSubIdToNewSubId[oldId] = newSubId;
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
                if (GetUserByName(u.username, existing)) {
                    u.id = existing.id;
                    UpdateUser(u);
                } else {
                    AddUser(u);
                }
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

                if (AddProxyPort(p)) {
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
                        UpdateRoutingRule(r);
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
                        UpdateRoutingRule(r);
                        continue;
                    }
                }

                AddRoutingRule(r);
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
                if (!ip.empty()) AddToBlacklist(ip, remark);
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

        ExecuteSQL("COMMIT;");
        return true;
    } catch (const std::exception& e) {
        ExecuteSQL("ROLLBACK;");
        errorMsg = std::string("导入异常: ") + e.what();
        return false;
    }
}

