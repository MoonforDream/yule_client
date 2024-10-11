// log.h
#ifndef LOG_H
#define LOG_H

#include "tool.h"
#include <windivert.h>
#include <spdlog/spdlog.h>
#include <spdlog/async.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <string>

extern int log_thread;

// 初始化日志系统
void init_logging();

// 日志级别
enum class LogLevel {
    trace,
    debug,
    info,
    warn,
    err,
    critical
};

// 写日志的函数
void log(const std::string& message, LogLevel level = LogLevel::info);
//转发日志
void log_redirect(UINT32 srcAddr, USHORT srcPort, UINT32 proxyAddr, USHORT proxyPort, UINT32 dstAddr, USHORT dstPort, int direction, int o_protocol, int n_protocol);
void log_redirect(log_s &lgs,int flags);

//报错打印
void error_handling(const std::string& error_message);

#endif // LOG_H
