// 此文件专门用于生成编译时间戳版本号
// CMake 配置会在每次构建时强制重新编译此文件
// 这样可以确保 __DATE__ 和 __TIME__ 宏始终反映最新的编译时间

#include "Version.h"
#include <cstdio>

namespace Version {

// 编译时间戳 - 每次编译更新
static const char* const BUILD_TIMESTAMP = __DATE__ " " __TIME__;

// 获取构建时间戳
const char* GetBuildTimestamp() {
    return BUILD_TIMESTAMP;
}

// 将 __DATE__ (格式 "Feb  4 2026") 和 __TIME__ (格式 "09:13:12") 转换为 YYYYMMDDHHMM 格式
std::string GetBuildDateTime() {
    const char* date = __DATE__;  // "Feb  4 2026"
    const char* time = __TIME__;  // "09:13:12"
    
    // 月份映射
    const char* months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    int month = 0;
    for (int i = 0; i < 12; i++) {
        if (date[0] == months[i][0] && date[1] == months[i][1] && date[2] == months[i][2]) {
            month = i + 1;
            break;
        }
    }
    
    // 解析日期
    int day = (date[4] == ' ' ? 0 : (date[4] - '0') * 10) + (date[5] - '0');
    int year = (date[7] - '0') * 1000 + (date[8] - '0') * 100 + 
               (date[9] - '0') * 10 + (date[10] - '0');
    
    // 解析时间
    int hour = (time[0] - '0') * 10 + (time[1] - '0');
    int minute = (time[3] - '0') * 10 + (time[4] - '0');
    
    // 格式化为 YYYYMMDDHHMM
    char buf[16];
    snprintf(buf, sizeof(buf), "%04d%02d%02d%02d%02d", year, month, day, hour, minute);
    return std::string(buf);
}

std::string GetVersion() {
    return std::string(APP_VERSION_MAJOR) + "." + APP_VERSION_MINOR + "." + GetBuildDateTime();
}

std::wstring GetVersionW() {
    std::string ver = GetVersion();
    return std::wstring(ver.begin(), ver.end());
}

std::wstring GetFullTitleW() {
    return std::wstring(APP_NAME_W) + L" v" + GetVersionW() + L" - " + APP_DESCRIPTION_W;
}

} // namespace Version
