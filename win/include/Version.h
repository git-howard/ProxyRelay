#pragma once

#include <string>

// 程序版本号
// 格式: 主版本.次版本.YYYYMMDDHHMM (年月日时分)
// Version.cpp 每次编译都会重新生成，确保时间戳是最新的

#define APP_VERSION_MAJOR "1"
#define APP_VERSION_MINOR "0"

// 版本信息
#define APP_NAME "ProxyRelay"
#define APP_NAME_W L"ProxyRelay"
#define APP_DESCRIPTION "二级代理管理器"
#define APP_DESCRIPTION_W L"二级代理管理器"
#define APP_COPYRIGHT "© 2026 ProxyRelay"

namespace Version {
    // 获取构建时间戳（在 Version.cpp 中实现，每次编译更新）
    const char* GetBuildTimestamp();
    
    // 将 __DATE__ 和 __TIME__ 转换为 YYYYMMDDHHMM 格式
    std::string GetBuildDateTime();
    
    // 获取完整版本号，格式：1.0.YYYYMMDDHHMM
    std::string GetVersion();
    
    // 获取宽字符版本号
    std::wstring GetVersionW();
    
    // 获取完整窗口标题
    std::wstring GetFullTitleW();
}
