#pragma once

#include "pch.h"
#include <commctrl.h>
#include <shellapi.h>
#include <vector>
#include <string>

struct ConnectionLogEntry;

// 窗口控件ID
#define IDC_TAB_MAIN        1001

// 用户管理
#define IDC_LIST_USERS      2001
#define IDC_BTN_ADD_USER    2010
#define IDC_BTN_EDIT_USER   2011
#define IDC_BTN_DEL_USER    2012

// 端口管理
#define IDC_LIST_PORTS      3001
#define IDC_BTN_ADD_PORT    3010
#define IDC_BTN_EDIT_PORT   3011
#define IDC_BTN_DEL_PORT    3012

// 流量统计
#define IDC_COMBO_USER      4001
#define IDC_LIST_TRAFFIC    4002
#define IDC_STATIC_TRAFFIC  4010

// 日志
#define IDC_LIST_LOGS       5001

// 定时器
#define IDT_REFRESH         6001
#define IDT_TRAFFIC_GRAPH   6002

// 自定义消息
#define WM_ADD_LOG_ENTRY    (WM_USER + 100)
#define WM_TRAYICON         (WM_USER + 101)

// 托盘菜单ID
#define ID_TRAY_SHOW        7001
#define ID_TRAY_AUTOSTART   7002
#define ID_TRAY_EXIT        7003

// 窗口菜单ID
#define ID_MENU_SETTINGS    8001
#define ID_MENU_AUTOSTART   8002
#define ID_MENU_ABOUT       8003
#define ID_MENU_EXIT        8004

// 右键菜单ID
#define ID_CTX_EDIT         9001
#define ID_CTX_DELETE       9002
#define ID_CTX_TOGGLE       9003  // 暂停/启用
#define ID_CTX_MOVE_UP      9004  // 上移
#define ID_CTX_MOVE_DOWN    9005  // 下移
#define ID_CTX_COPY_IP      9006  // 复制IP
#define ID_CTX_COPY_ADDRESS 9007  // 复制地址

class MainWindow {
public:
    static MainWindow& Instance();
    
    bool Create(HINSTANCE hInstance);
    int Run();
    
    HWND GetHandle() const { return hwnd_; }
    void UpdateStatus();
    void RefreshUserList();
    void RefreshPortList();
    void RefreshTrafficGraph();
    
    // 添加日志条目（可从其他线程调用）
    void AddLogEntry(const ConnectionLogEntry& entry);
    
private:
    MainWindow() = default;
    ~MainWindow();
    
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);
    
    void CreateControls();
    void CreateUserPage();
    void CreatePortPage();
    void CreateTrafficPage();
    void CreateLogPage();
    void CreateStatusBar();
    
    void OnSize(int width, int height);
    void OnTabChange();
    void OnCommand(WPARAM wParam);
    void OnTimer(WPARAM timerId);
    void OnPaint();
    
    // 用户对话框
    void ShowAddUserDialog();
    void ShowEditUserDialog();
    void DeleteSelectedUser();
    
    // 端口对话框
    void ShowAddPortDialog();
    void ShowEditPortDialog();
    void DeleteSelectedPort();
    void ToggleSelectedUser();
    void ToggleSelectedPort();
    void MoveSelectedUserUp();
    void MoveSelectedUserDown();
    void MoveSelectedPortUp();
    void MoveSelectedPortDown();
    
    // 关于对话框
    void ShowAboutDialog();
    
    // 绘制流量图
    void DrawTrafficGraph(HDC hdc, RECT& rect);
    
    // 日志相关
    void RefreshLogList();
    void ClearLogs();
    
    // 刷新端口流量
    void UpdatePortStats();
    
    // 托盘相关
    void CreateTrayIcon();
    void RemoveTrayIcon();
    void ShowTrayMenu();
    void MinimizeToTray();
    void RestoreFromTray();
    
    // 开机自启
    bool IsAutoStartEnabled();
    void SetAutoStart(bool enable);
    
    HWND hwnd_ = nullptr;
    HWND hTab_ = nullptr;
    HWND hStatusBar_ = nullptr;
    
    // Tab页面控件
    HWND hUserPage_ = nullptr;
    HWND hPortPage_ = nullptr;
    HWND hTrafficPage_ = nullptr;
    HWND hLogPage_ = nullptr;
    
    // 用户列表
    HWND hUserList_ = nullptr;
    
    // 端口列表
    HWND hPortList_ = nullptr;
    
    // 流量页面
    HWND hUserCombo_ = nullptr;
    HWND hTrafficList_ = nullptr;
    HWND hTrafficGraph_ = nullptr;
    
    // 日志页面
    HWND hLogList_ = nullptr;
    
    HINSTANCE hInstance_ = nullptr;
    int currentTab_ = 0;
    HWND hToolTip_ = nullptr;
    
    // 托盘图标
    NOTIFYICONDATAW nid_ = {};
    bool trayIconCreated_ = false;
    
    // 流量图数据
    // 流量图数据
    std::vector<int64_t> uploadHistory_;
    std::vector<int64_t> downloadHistory_;

    // 封禁管理页面
    void CreateBanPage();
    void RefreshBanList();
    void OnBanTypeChanged();
    void ShowAddBanDialog();
    void ShowEditBanDialog();
    void DeleteSelectedBan();
    void SaveBanSettings();
    int currentBanType_ = 0; // 0: Whitelist, 1: Blacklist, 2: AutoBan, 3: No-Auth IP
    HWND hBanList_ = nullptr;
    HWND hBanTypeCombo_ = nullptr;

    // 黑名单页面 (废弃/合并到Ban页面)
    // HWND hBlacklistPage_ = nullptr;
    // HWND hBlacklistEdit_ = nullptr;
    // void CreateBlacklistPage();
    // void SaveBlacklist();

    // Bypass页面
    HWND hBypassPage_ = nullptr;
    void CreateBypassPage();
    void SaveBypassConfig();
    void UpdateRules();
    
    // 路由规则编辑框（动态生成：第一个是直连规则，后面是各代理的规则）
    struct RoutingRuleEdit {
        int proxyId;           // 0=直连，>0=代理ID
        std::wstring label;    // 标签文本
        HWND hLabel;           // 标签控件
        HWND hEdit;            // 编辑框控件
        HWND hPriorityLabel;   // 优先级标签
        HWND hPriorityEdit;    // 优先级输入框
    };
    std::vector<RoutingRuleEdit> routingRuleEdits_;
    void CreateRoutingRuleEditors();
    void SaveAllRoutingRules();
    void LoadAllRoutingRules();

    // 系统设置页面
    HWND hSettingsPage_ = nullptr;
    void CreateSettingsPage();
    void SaveSettings();
};

// 新增ID
#define IDC_EDIT_BLACKLIST      10001
#define IDC_BTN_SAVE_BL         10002
#define IDC_CHK_CHNROUTE        10003
#define IDC_CHK_CHNROUTE6       10004
#define IDC_CHK_CHNLIST         10005
#define IDC_EDIT_CUSTOM_BYPASS  10006
#define IDC_BTN_UPDATE_RULES    10007
#define IDC_BTN_SAVE_BYPASS     10008

// 系统设置页面ID
#define IDC_EDIT_SETTINGS_AUTO_PORT     11001
#define IDC_EDIT_SETTINGS_TCPING        11002
#define IDC_BTN_SAVE_SETTINGS           11003
#define IDC_STATIC_SETTINGS_LABEL       11004
#define IDC_STATIC_SETTINGS_TCPING      11005
#define IDC_EDIT_SETTINGS_LOG_DAYS      11006
#define IDC_STATIC_SETTINGS_LOG_DAYS    11007
#define IDC_EDIT_SETTINGS_BUFFER_SIZE   11008
#define IDC_STATIC_SETTINGS_BUFFER_SIZE 11009

// 路由规则页面ID
#define IDC_LIST_ROUTING_RULES          12001
#define IDC_BTN_ADD_ROUTING_RULE        12002
#define IDC_BTN_EDIT_ROUTING_RULE       12003
#define IDC_BTN_DEL_ROUTING_RULE        12004

// 封禁管理页面ID
#define IDC_COMBO_BAN_TYPE       13000
#define IDC_LIST_BAN             13001
#define IDC_BTN_ADD_BAN          13002
#define IDC_BTN_DEL_BAN          13003
#define IDC_EDIT_M               13004
#define IDC_EDIT_N               13005
#define IDC_EDIT_T               13006
#define IDC_BTN_SAVE_BAN_SETTINGS 13007
#define IDC_STATIC_BAN_M         13008
#define IDC_STATIC_BAN_N         13009
#define IDC_STATIC_BAN_T         13010
#define IDC_STATIC_BAN_MINUTES   13011


