#include "Logger.h"
using namespace std;
int main()
{
    // 获取 Logger 实例
    auto& logger = tn_loam::Logger::getInstance();

    // 设置日志级别为 DEBUG
    logger.setLogLevel(tn_loam::LogLevel::DEBUG);

    // 启用控制台输出
    logger.setConsoleOutput(true);

    // 启用文件输出并设置日志文件路径
    if (!logger.setLogFile("application.log")) {
        std::cout<< "无法设置日志文件，程序退出。"<<std::endl;
        return -1;
    }
    logger.setFileOutput(true);

    // 记录不同级别的日志
    LOG_DEBUG("This is a debug log");
    LOG_INFO("这是一个信息日志");
    LOG_WARN("这是一个警告日志");
    LOG_ERROR("这是一个错误日志");
    LOG_FATAL("这是一个致命错误日志");

    // 使用格式化日志
    LOG_INFOF("程序运行到第 %d 步，状态: %s", 42, "正常");

    return 0;
}