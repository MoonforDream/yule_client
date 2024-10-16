#include "log.h"

int log_thread=1;

void init_logging() {
    // 设置异步日志队列大小和线程数
    spdlog::init_thread_pool(8192, log_thread);

    // 创建彩色控制台接收器
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    auto logger = std::make_shared<spdlog::async_logger>("proxy_logger", console_sink, spdlog::thread_pool(), spdlog::async_overflow_policy::block);

    spdlog::register_logger(logger);
    spdlog::set_default_logger(logger);
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v"); // 彩色日志输出
//    spdlog::set_level(spdlog::level::trace); // 默认日志级别为 trace
    spdlog::set_level(spdlog::level::info);
}

void log(const std::string& message, LogLevel level) {
    switch (level) {
        case LogLevel::trace:
            spdlog::trace(message);
            break;
        case LogLevel::debug:
            spdlog::debug(message);
            break;
        case LogLevel::info:
            spdlog::info(message);
            break;
        case LogLevel::warn:
            spdlog::warn(message);
            break;
        case LogLevel::err:
            spdlog::error(message);
            break;
        case LogLevel::critical:
            spdlog::critical(message);
            break;
    }
}

void log_redirect(UINT32 srcAddr, USHORT srcPort, UINT32 proxyAddr, USHORT proxyPort, UINT32 dstAddr, USHORT dstPort, int direction, int o_protocol, int n_protocol) {
    const char *o_s = o_protocol ? "UDP" : "TCP";
    const char *n_s = n_protocol ? "UDP" : "TCP";
    std::string message = fmt::format("[{}] ({})[{}:{} -> {}:{}] -> ({})[{}:{} -> {}:{}] ",
                                      direction == 0 ? "Redirect" : "Received",o_s,
                                      ConvertIP(srcAddr), ntohs(srcPort), ConvertIP(dstAddr), ntohs(dstPort),
                                      n_s, ConvertIP(srcAddr), ntohs(srcPort), ConvertIP(proxyAddr), ntohs(proxyPort));
    log(message, LogLevel::info);
}

void log_redirect(log_s &lgs,int flags){
    const char *o_s = lgs.o_protocol ? "UDP" : "TCP";
    const char *n_s = lgs.n_protocol ? "UDP" : "TCP";
    std::string message = fmt::format("[{}] ({})[{}:{} -> {}:{}] -> ({})[{}:{} -> {}:{}] ",
                                      flags == 0 ? "Redirect" : "Received",o_s,
                                      ConvertIP(lgs.o_srcaddr), ntohs(lgs.o_srcport), ConvertIP(lgs.o_dstaddr), ntohs(lgs.o_dstport),
                                      n_s, ConvertIP(lgs.n_srcaddr), ntohs(lgs.n_srcport), ConvertIP(lgs.n_dstaddr), ntohs(lgs.n_dstport));
    log(message, LogLevel::info);
}

void error_handling(const std::string& error_message) {
    log(error_message, LogLevel::err);
}