#include "Database.h"
#include "Utils.h"
#include <sstream>

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
    
    // 启用WAL模式提高性能
    ExecuteSQL("PRAGMA journal_mode=WAL;");
    ExecuteSQL("PRAGMA synchronous=NORMAL;");
    
    return CreateTables();
}

void Database::Close() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
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
            priority INTEGER DEFAULT 0,
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
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
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
    
    // 如果没有用户，创建默认管理员 (直接使用SQL避免死锁)
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM users", -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            if (sqlite3_column_int(stmt, 0) == 0) {
                sqlite3_finalize(stmt);
                // 直接插入默认用户，不调用AddUser()以避免死锁
                const char* insertSql = R"(
                    INSERT INTO users (username, password, allowed_ips, daily_limit, monthly_limit, enabled)
                    VALUES ('admin', 'admin123', '*', 0, 0, 1);
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
        INSERT INTO users (username, password, allowed_ips, daily_limit, monthly_limit, enabled, remark, expiry_date, priority)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, (SELECT COALESCE(MAX(priority), 0) + 1 FROM users));
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
    sqlite3_bind_int(stmt, 9, user.id);
    
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
    const char* sql = "SELECT id, username, password, allowed_ips, daily_limit, monthly_limit, enabled, remark, expiry_date, priority, created_at, updated_at FROM users WHERE id = ?";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, userId);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        user.id = sqlite3_column_int(stmt, 0);
        user.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        user.password = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        user.allowedIPs = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        user.dailyLimit = sqlite3_column_int64(stmt, 4);
        user.monthlyLimit = sqlite3_column_int64(stmt, 5);
        user.enabled = sqlite3_column_int(stmt, 6) != 0;
        const char* remark = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        user.remark = remark ? remark : "";
        const char* expiryDate = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
        user.expiryDate = expiryDate ? expiryDate : "";
        user.priority = sqlite3_column_int(stmt, 9);
        user.createdAt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
        user.updatedAt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));
        sqlite3_finalize(stmt);
        return true;
    }
    
    sqlite3_finalize(stmt);
    return false;
}

bool Database::GetUserByName(const std::string& username, UserInfo& user) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT id, username, password, allowed_ips, daily_limit, monthly_limit, enabled, remark, expiry_date, priority, created_at, updated_at FROM users WHERE username = ?";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        user.id = sqlite3_column_int(stmt, 0);
        user.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        user.password = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        const char* ips = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        user.allowedIPs = ips ? ips : "*";
        user.dailyLimit = sqlite3_column_int64(stmt, 4);
        user.monthlyLimit = sqlite3_column_int64(stmt, 5);
        user.enabled = sqlite3_column_int(stmt, 6) != 0;
        const char* remark = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        user.remark = remark ? remark : "";
        const char* expiryDate = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
        user.expiryDate = expiryDate ? expiryDate : "";
        user.priority = sqlite3_column_int(stmt, 9);
        const char* created = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
        user.createdAt = created ? created : "";
        const char* updated = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));
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
    const char* sql = "SELECT id, username, password, allowed_ips, daily_limit, monthly_limit, enabled, remark, expiry_date, priority, created_at, updated_at FROM users ORDER BY priority ASC, id ASC";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return users;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        UserInfo user;
        user.id = sqlite3_column_int(stmt, 0);
        user.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        user.password = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        const char* ips = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        user.allowedIPs = ips ? ips : "*";
        user.dailyLimit = sqlite3_column_int64(stmt, 4);
        user.monthlyLimit = sqlite3_column_int64(stmt, 5);
        user.enabled = sqlite3_column_int(stmt, 6) != 0;
        const char* remark = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        user.remark = remark ? remark : "";
        const char* expiryDate = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
        user.expiryDate = expiryDate ? expiryDate : "";
        user.priority = sqlite3_column_int(stmt, 9);
        const char* created = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
        user.createdAt = created ? created : "";
        const char* updated = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));
        user.updatedAt = updated ? updated : "";
        users.push_back(user);
    }
    
    sqlite3_finalize(stmt);
    return users;
}

bool Database::MoveUserUp(int userId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    int currentPriority = 0;
    {
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, "SELECT priority FROM users WHERE id = ?", -1, &stmt, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_int(stmt, 1, userId);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            currentPriority = sqlite3_column_int(stmt, 0);
        } else {
            sqlite3_finalize(stmt);
            return false;
        }
        sqlite3_finalize(stmt);
    }
    
    int prevId = -1;
    int prevPriority = -1;
    {
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, "SELECT id, priority FROM users WHERE priority < ? ORDER BY priority DESC LIMIT 1", -1, &stmt, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_int(stmt, 1, currentPriority);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            prevId = sqlite3_column_int(stmt, 0);
            prevPriority = sqlite3_column_int(stmt, 1);
        }
        sqlite3_finalize(stmt);
    }
    
    if (prevId == -1) return false;
    
    std::string sql1 = "UPDATE users SET priority = " + std::to_string(prevPriority) + " WHERE id = " + std::to_string(userId) + ";";
    ExecuteSQL(sql1);
    std::string sql2 = "UPDATE users SET priority = " + std::to_string(currentPriority) + " WHERE id = " + std::to_string(prevId) + ";";
    ExecuteSQL(sql2);
    
    return true;
}

bool Database::MoveUserDown(int userId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    int currentPriority = 0;
    {
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, "SELECT priority FROM users WHERE id = ?", -1, &stmt, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_int(stmt, 1, userId);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            currentPriority = sqlite3_column_int(stmt, 0);
        } else {
            sqlite3_finalize(stmt);
            return false;
        }
        sqlite3_finalize(stmt);
    }
    
    int nextId = -1;
    int nextPriority = -1;
    {
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, "SELECT id, priority FROM users WHERE priority > ? ORDER BY priority ASC LIMIT 1", -1, &stmt, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_int(stmt, 1, currentPriority);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            nextId = sqlite3_column_int(stmt, 0);
            nextPriority = sqlite3_column_int(stmt, 1);
        }
        sqlite3_finalize(stmt);
    }
    
    if (nextId == -1) return false;
    
    std::string sql1 = "UPDATE users SET priority = " + std::to_string(nextPriority) + " WHERE id = " + std::to_string(userId) + ";";
    ExecuteSQL(sql1);
    std::string sql2 = "UPDATE users SET priority = " + std::to_string(currentPriority) + " WHERE id = " + std::to_string(nextId) + ";";
    ExecuteSQL(sql2);
    
    return true;
}

// 代理端口管理
bool Database::AddProxyPort(const ProxyPort& port) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    const char* sql = R"(
        INSERT INTO proxy_ports (listen_port, upstream_type, upstream_host, upstream_port, 
                                 upstream_user, upstream_pass, enabled, description, priority)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, (SELECT COALESCE(MAX(priority), 0) + 1 FROM proxy_ports));
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
    sqlite3_bind_text(stmt, 8, port.description.c_str(), -1, SQLITE_TRANSIENT);
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::UpdateProxyPort(const ProxyPort& port) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    const char* sql = R"(
        UPDATE proxy_ports SET 
            listen_port = ?, upstream_type = ?, upstream_host = ?, upstream_port = ?,
            upstream_user = ?, upstream_pass = ?, enabled = ?, description = ?
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
    sqlite3_bind_text(stmt, 8, port.description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 9, port.id);
    
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
    const char* sql = "SELECT id, listen_port, upstream_type, upstream_host, upstream_port, upstream_user, upstream_pass, enabled, description, priority, created_at FROM proxy_ports WHERE id = ?";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, portId);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        port.id = sqlite3_column_int(stmt, 0);
        port.listenPort = sqlite3_column_int(stmt, 1);
        port.upstreamType = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        port.upstreamHost = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
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
    const char* sql = "SELECT id, listen_port, upstream_type, upstream_host, upstream_port, upstream_user, upstream_pass, enabled, description, priority, created_at FROM proxy_ports ORDER BY priority ASC, listen_port ASC";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return ports;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ProxyPort port;
        port.id = sqlite3_column_int(stmt, 0);
        port.listenPort = sqlite3_column_int(stmt, 1);
        port.upstreamType = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        port.upstreamHost = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
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
        ports.push_back(port);
    }
    
    sqlite3_finalize(stmt);
    return ports;
}

std::vector<ProxyPort> Database::GetEnabledProxyPorts() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<ProxyPort> ports;
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT id, listen_port, upstream_type, upstream_host, upstream_port, upstream_user, upstream_pass, enabled, description, priority, created_at FROM proxy_ports WHERE enabled = 1 ORDER BY priority ASC, listen_port ASC";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return ports;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ProxyPort port;
        port.id = sqlite3_column_int(stmt, 0);
        port.listenPort = sqlite3_column_int(stmt, 1);
        port.upstreamType = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        port.upstreamHost = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
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
        ports.push_back(port);
    }
    
    sqlite3_finalize(stmt);
    return ports;
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

bool Database::GetDailyTraffic(int userId, const std::string& date, TrafficRecord& record) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, "SELECT * FROM traffic_records WHERE user_id = ? AND date = ?", -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
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
        sqlite3_finalize(stmt);
        return true;
    }
    
    sqlite3_finalize(stmt);
    return false;
}

bool Database::GetMonthlyTraffic(int userId, const std::string& month, int64_t& upload, int64_t& download) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    std::string pattern = month + "%";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, 
        "SELECT SUM(upload_bytes), SUM(download_bytes) FROM traffic_records WHERE user_id = ? AND date LIKE ?", 
        -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, userId);
    sqlite3_bind_text(stmt, 2, pattern.c_str(), -1, SQLITE_TRANSIENT);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        upload = sqlite3_column_int64(stmt, 0);
        download = sqlite3_column_int64(stmt, 1);
        sqlite3_finalize(stmt);
        return true;
    }
    
    sqlite3_finalize(stmt);
    return false;
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
    TrafficRecord record;
    if (GetDailyTraffic(userId, Utils::GetCurrentDate(), record)) {
        return record.uploadBytes + record.downloadBytes;
    }
    return 0;
}

int64_t Database::GetUserMonthlyUsage(int userId) {
    int64_t upload = 0, download = 0;
    if (GetMonthlyTraffic(userId, Utils::GetCurrentMonth(), upload, download)) {
        return upload + download;
    }
    return 0;
}

int64_t Database::GetUserLastMonthUsage(int userId) {
    int64_t upload = 0, download = 0;
    if (GetMonthlyTraffic(userId, Utils::GetLastMonth(), upload, download)) {
        return upload + download;
    }
    return 0;
}

int64_t Database::GetUserTotalUsage(int userId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, 
        "SELECT SUM(upload_bytes), SUM(download_bytes) FROM traffic_records WHERE user_id = ?", 
        -1, &stmt, nullptr) != SQLITE_OK) {
        return 0;
    }
    
    sqlite3_bind_int(stmt, 1, userId);
    
    int64_t total = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int64_t upload = sqlite3_column_int64(stmt, 0);
        int64_t download = sqlite3_column_int64(stmt, 1);
        total = upload + download;
    }
    
    sqlite3_finalize(stmt);
    return total;
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

// 优先级调整
bool Database::MoveProxyPortUp(int portId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    // 1. 获取当前port的priority
    int currentPriority = 0;
    {
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, "SELECT priority FROM proxy_ports WHERE id = ?", -1, &stmt, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_int(stmt, 1, portId);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            currentPriority = sqlite3_column_int(stmt, 0);
        } else {
            sqlite3_finalize(stmt);
            return false;
        }
        sqlite3_finalize(stmt);
    }
    
    // 2. 找到比当前priority小的最大priority（即上一条）
    int prevId = -1;
    int prevPriority = -1;
    {
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, "SELECT id, priority FROM proxy_ports WHERE priority < ? ORDER BY priority DESC LIMIT 1", -1, &stmt, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_int(stmt, 1, currentPriority);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            prevId = sqlite3_column_int(stmt, 0);
            prevPriority = sqlite3_column_int(stmt, 1);
        }
        sqlite3_finalize(stmt);
    }
    
    if (prevId == -1) return false; // 已经是第一条
    
    // 3. 交换priority
    std::string sql1 = "UPDATE proxy_ports SET priority = " + std::to_string(prevPriority) + " WHERE id = " + std::to_string(portId) + ";";
    ExecuteSQL(sql1);
    std::string sql2 = "UPDATE proxy_ports SET priority = " + std::to_string(currentPriority) + " WHERE id = " + std::to_string(prevId) + ";";
    ExecuteSQL(sql2);
    
    return true;
}

bool Database::MoveProxyPortDown(int portId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    // 1. 获取当前port的priority
    int currentPriority = 0;
    {
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, "SELECT priority FROM proxy_ports WHERE id = ?", -1, &stmt, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_int(stmt, 1, portId);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            currentPriority = sqlite3_column_int(stmt, 0);
        } else {
            sqlite3_finalize(stmt);
            return false;
        }
        sqlite3_finalize(stmt);
    }
    
    // 2. 找到比当前priority大的最小priority（即下一条）
    int nextId = -1;
    int nextPriority = -1;
    {
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, "SELECT id, priority FROM proxy_ports WHERE priority > ? ORDER BY priority ASC LIMIT 1", -1, &stmt, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_int(stmt, 1, currentPriority);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            nextId = sqlite3_column_int(stmt, 0);
            nextPriority = sqlite3_column_int(stmt, 1);
        }
        sqlite3_finalize(stmt);
    }
    
    if (nextId == -1) return false; // 已经是最后一条
    
    // 3. 交换priority
    std::string sql1 = "UPDATE proxy_ports SET priority = " + std::to_string(nextPriority) + " WHERE id = " + std::to_string(portId) + ";";
    ExecuteSQL(sql1);
    std::string sql2 = "UPDATE proxy_ports SET priority = " + std::to_string(currentPriority) + " WHERE id = " + std::to_string(nextId) + ";";
    ExecuteSQL(sql2);
    
    return true;
}

// 路由规则管理
bool Database::AddRoutingRule(const RoutingRule& rule) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    const char* sql = R"(
        INSERT INTO routing_rules (priority, match_type, match_value, proxy_id, enabled, description)
        VALUES (?, ?, ?, ?, ?, ?);
    )";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, rule.priority);
    sqlite3_bind_text(stmt, 2, rule.matchType.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, rule.matchValue.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, rule.proxyId);
    sqlite3_bind_int(stmt, 5, rule.enabled ? 1 : 0);
    sqlite3_bind_text(stmt, 6, rule.description.c_str(), -1, SQLITE_TRANSIENT);
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::UpdateRoutingRule(const RoutingRule& rule) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    const char* sql = R"(
        UPDATE routing_rules SET 
            match_type = ?, match_value = ?, proxy_id = ?, enabled = ?, description = ?
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
    sqlite3_bind_int(stmt, 6, rule.id);
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::DeleteRoutingRule(int ruleId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, "DELETE FROM routing_rules WHERE id = ?", -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, ruleId);
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::GetRoutingRule(int ruleId, RoutingRule& rule) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT id, priority, match_type, match_value, proxy_id, enabled, description, created_at FROM routing_rules WHERE id = ?";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, ruleId);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        rule.id = sqlite3_column_int(stmt, 0);
        rule.priority = sqlite3_column_int(stmt, 1);
        rule.matchType = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        rule.matchValue = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        rule.proxyId = sqlite3_column_int(stmt, 4);
        rule.enabled = sqlite3_column_int(stmt, 5) != 0;
        const char* desc = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        rule.description = desc ? desc : "";
        const char* created = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        rule.createdAt = created ? created : "";
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
    const char* sql = "SELECT id, priority, match_type, match_value, proxy_id, enabled, description, created_at FROM routing_rules ORDER BY priority ASC";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return rules;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        RoutingRule rule;
        rule.id = sqlite3_column_int(stmt, 0);
        rule.priority = sqlite3_column_int(stmt, 1);
        rule.matchType = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        rule.matchValue = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        rule.proxyId = sqlite3_column_int(stmt, 4);
        rule.enabled = sqlite3_column_int(stmt, 5) != 0;
        const char* desc = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        rule.description = desc ? desc : "";
        const char* created = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        rule.createdAt = created ? created : "";
        rules.push_back(rule);
    }
    
    sqlite3_finalize(stmt);
    return rules;
}

std::vector<RoutingRule> Database::GetEnabledRoutingRules() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    std::vector<RoutingRule> rules;
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT id, priority, match_type, match_value, proxy_id, enabled, description, created_at FROM routing_rules WHERE enabled = 1 ORDER BY priority ASC";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return rules;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        RoutingRule rule;
        rule.id = sqlite3_column_int(stmt, 0);
        rule.priority = sqlite3_column_int(stmt, 1);
        rule.matchType = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        rule.matchValue = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        rule.proxyId = sqlite3_column_int(stmt, 4);
        rule.enabled = true;
        const char* desc = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        rule.description = desc ? desc : "";
        const char* created = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        rule.createdAt = created ? created : "";
        rules.push_back(rule);
    }
    
    sqlite3_finalize(stmt);
    return rules;
}

bool Database::MoveRoutingRuleUp(int ruleId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    int currentPriority = 0;
    {
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, "SELECT priority FROM routing_rules WHERE id = ?", -1, &stmt, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_int(stmt, 1, ruleId);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            currentPriority = sqlite3_column_int(stmt, 0);
        } else {
            sqlite3_finalize(stmt);
            return false;
        }
        sqlite3_finalize(stmt);
    }
    
    int prevId = -1;
    int prevPriority = -1;
    {
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, "SELECT id, priority FROM routing_rules WHERE priority < ? ORDER BY priority DESC LIMIT 1", -1, &stmt, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_int(stmt, 1, currentPriority);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            prevId = sqlite3_column_int(stmt, 0);
            prevPriority = sqlite3_column_int(stmt, 1);
        }
        sqlite3_finalize(stmt);
    }
    
    if (prevId == -1) return false;
    
    std::string sql1 = "UPDATE routing_rules SET priority = " + std::to_string(prevPriority) + " WHERE id = " + std::to_string(ruleId) + ";";
    ExecuteSQL(sql1);
    std::string sql2 = "UPDATE routing_rules SET priority = " + std::to_string(currentPriority) + " WHERE id = " + std::to_string(prevId) + ";";
    ExecuteSQL(sql2);
    
    return true;
}

bool Database::MoveRoutingRuleDown(int ruleId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    int currentPriority = 0;
    {
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, "SELECT priority FROM routing_rules WHERE id = ?", -1, &stmt, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_int(stmt, 1, ruleId);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            currentPriority = sqlite3_column_int(stmt, 0);
        } else {
            sqlite3_finalize(stmt);
            return false;
        }
        sqlite3_finalize(stmt);
    }
    
    int nextId = -1;
    int nextPriority = -1;
    {
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, "SELECT id, priority FROM routing_rules WHERE priority > ? ORDER BY priority ASC LIMIT 1", -1, &stmt, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_int(stmt, 1, currentPriority);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            nextId = sqlite3_column_int(stmt, 0);
            nextPriority = sqlite3_column_int(stmt, 1);
        }
        sqlite3_finalize(stmt);
    }
    
    if (nextId == -1) return false;
    
    std::string sql1 = "UPDATE routing_rules SET priority = " + std::to_string(nextPriority) + " WHERE id = " + std::to_string(ruleId) + ";";
    ExecuteSQL(sql1);
    std::string sql2 = "UPDATE routing_rules SET priority = " + std::to_string(currentPriority) + " WHERE id = " + std::to_string(nextId) + ";";
    ExecuteSQL(sql2);
    
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
