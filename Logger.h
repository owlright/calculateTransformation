#pragma once
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>

namespace tn_loam {

/**
 * @brief 日志级别枚举
 */
enum class LogLevel {
    DEBUG = 0, // 调试信息
    INFO = 1,  // 一般信息
    WARN = 2,  // 警告信息
    ERROR = 3, // 错误信息
    FATAL = 4  // 致命错误
};

/**
 * @brief 日志记录器类
 *
 * 使用单例模式实现的日志记录器，可以记录不同级别的日志信息
 * 并支持输出到控制台和文件
 */
class Logger {
  public:
    /**
     * @brief 获取Logger实例
     * @return Logger单例实例
     */
    static Logger& getInstance() {
        static Logger instance;
        return instance;
    }

    /**
     * @brief 设置日志级别
     * @param level 日志级别
     */
    void setLogLevel(LogLevel level) {
        level_ = level;
    }

    /**
     * @brief 获取当前日志级别
     * @return 当前日志级别
     */
    LogLevel getLogLevel() const {
        return level_;
    }

    /**
     * @brief 设置是否输出到控制台
     * @param enable 是否启用控制台输出
     */
    void setConsoleOutput(bool enable) {
        consoleOutput_ = enable;
    }

    /**
     * @brief 设置是否输出到文件
     * @param enable 是否启用文件输出
     */
    void setFileOutput(bool enable) {
        fileOutput_ = enable;
    }

    /**
     * @brief 设置日志文件路径
     * @param filePath 日志文件路径
     * @return 是否成功设置
     */
    bool setLogFile(const std::string& filePath) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (logFile_.is_open()) {
            logFile_.close();
        }

        logFile_.open(filePath, std::ios::out | std::ios::app);
        if (!logFile_.is_open()) {
            std::cerr << "无法打开日志文件: " << filePath << std::endl;
            return false;
        }

        logFilePath_ = filePath;
        return true;
    }

    /**
     * @brief 记录调试级别日志
     * @param message 日志消息
     */
    void debug(const std::string& message) {
        log(LogLevel::DEBUG, message);
    }

    /**
     * @brief 记录信息级别日志
     * @param message 日志消息
     */
    void info(const std::string& message) {
        log(LogLevel::INFO, message);
    }

    /**
     * @brief 记录警告级别日志
     * @param message 日志消息
     */
    void warn(const std::string& message) {
        log(LogLevel::WARN, message);
    }

    /**
     * @brief 记录错误级别日志
     * @param message 日志消息
     */
    void error(const std::string& message) {
        log(LogLevel::ERROR, message);
    }

    /**
     * @brief 记录致命错误级别日志
     * @param message 日志消息
     */
    void fatal(const std::string& message) {
        log(LogLevel::FATAL, message);
    }

    /**
     * @brief 格式化并记录调试级别日志
     * @tparam Args 可变参数类型
     * @param format 格式化字符串
     * @param args 格式化参数
     */
    template <typename... Args> void debugf(const std::string& format, Args... args) {
        if (level_ <= LogLevel::DEBUG) {
            logf(LogLevel::DEBUG, format, args...);
        }
    }

    /**
     * @brief 格式化并记录信息级别日志
     * @tparam Args 可变参数类型
     * @param format 格式化字符串
     * @param args 格式化参数
     */
    template <typename... Args> void infof(const std::string& format, Args... args) {
        if (level_ <= LogLevel::INFO) {
            logf(LogLevel::INFO, format, args...);
        }
    }

    /**
     * @brief 格式化并记录警告级别日志
     * @tparam Args 可变参数类型
     * @param format 格式化字符串
     * @param args 格式化参数
     */
    template <typename... Args> void warnf(const std::string& format, Args... args) {
        if (level_ <= LogLevel::WARN) {
            logf(LogLevel::WARN, format, args...);
        }
    }

    /**
     * @brief 格式化并记录错误级别日志
     * @tparam Args 可变参数类型
     * @param format 格式化字符串
     * @param args 格式化参数
     */
    template <typename... Args> void errorf(const std::string& format, Args... args) {
        if (level_ <= LogLevel::ERROR) {
            logf(LogLevel::ERROR, format, args...);
        }
    }

    /**
     * @brief 格式化并记录致命错误级别日志
     * @tparam Args 可变参数类型
     * @param format 格式化字符串
     * @param args 格式化参数
     */
    template <typename... Args> void fatalf(const std::string& format, Args... args) {
        if (level_ <= LogLevel::FATAL) {
            logf(LogLevel::FATAL, format, args...);
        }
    }

  private:
    Logger() : level_(LogLevel::INFO), consoleOutput_(true), fileOutput_(false) {
        // 在构造函数中初始化
    }

    ~Logger() {
        if (logFile_.is_open()) {
            logFile_.close();
        }
    }

    // 禁止拷贝构造和赋值操作
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    /**
     * @brief 记录日志
     * @param level 日志级别
     * @param message 日志消息
     */
    void log(LogLevel level, const std::string& message) {
        if (level < level_) {
            return;
        }

        std::string formattedMessage = formatLogMessage(level, message);

        std::lock_guard<std::mutex> lock(mutex_);

        if (consoleOutput_) {
            writeToConsole(level, formattedMessage);
        }

        if (fileOutput_ && logFile_.is_open()) {
            logFile_ << formattedMessage << std::endl;
            logFile_.flush();
        }
    }

    /**
     * @brief 格式化日志消息
     * @param level 日志级别
     * @param message 日志消息
     * @return 格式化后的消息
     */
    std::string formatLogMessage(LogLevel level, const std::string& message) {
        std::stringstream ss;

        // 获取当前时间
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        auto ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

        ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S") << '.' << std::setfill('0')
           << std::setw(3) << ms.count() << " [" << logLevelToString(level) << "] " << message;

        return ss.str();
    }

    /**
     * @brief 输出到控制台
     * @param level 日志级别
     * @param message 日志消息
     */
    void writeToConsole(LogLevel level, const std::string& message) {
        // 根据日志级别设置不同颜色
        switch (level) {
        case LogLevel::DEBUG:
            std::cout << "\033[37m" << message << "\033[0m" << std::endl; // 白色
            break;
        case LogLevel::INFO:
            std::cout << "\033[32m" << message << "\033[0m" << std::endl; // 绿色
            break;
        case LogLevel::WARN:
            std::cout << "\033[33m" << message << "\033[0m" << std::endl; // 黄色
            break;
        case LogLevel::ERROR:
            std::cerr << "\033[31m" << message << "\033[0m" << std::endl; // 红色
            break;
        case LogLevel::FATAL:
            std::cerr << "\033[35m" << message << "\033[0m" << std::endl; // 紫色
            break;
        default:
            std::cout << message << std::endl;
            break;
        }
    }

    /**
     * @brief 日志级别转字符串
     * @param level 日志级别
     * @return 日志级别字符串
     */
    std::string logLevelToString(LogLevel level) {
        switch (level) {
        case LogLevel::DEBUG:
            return "DEBUG";
        case LogLevel::INFO:
            return "INFO ";
        case LogLevel::WARN:
            return "WARN ";
        case LogLevel::ERROR:
            return "ERROR";
        case LogLevel::FATAL:
            return "FATAL";
        default:
            return "UNKNW";
        }
    }

    /**
     * @brief 格式化并记录日志
     * @tparam Args 可变参数类型
     * @param level 日志级别
     * @param format 格式化字符串
     * @param args 格式化参数
     */
    template <typename... Args> void logf(LogLevel level, const std::string& format, Args... args) {
        if (level < level_) {
            return;
        }

        std::string message = formatString(format, args...);
        log(level, message);
    }

    /**
     * @brief 格式化字符串
     * @tparam Args 可变参数类型
     * @param format 格式化字符串
     * @param args 格式化参数
     * @return 格式化后的字符串
     */
    template <typename... Args> std::string formatString(const std::string& format, Args... args) {
        size_t size = snprintf(nullptr, 0, format.c_str(), args...) + 1;
        std::unique_ptr<char[]> buf(new char[size]);
        snprintf(buf.get(), size, format.c_str(), args...);
        return std::string(buf.get(), buf.get() + size - 1);
    }

    LogLevel level_;          // 日志级别
    bool consoleOutput_;      // 是否输出到控制台
    bool fileOutput_;         // 是否输出到文件
    std::ofstream logFile_;   // 日志文件流
    std::string logFilePath_; // 日志文件路径
    std::mutex mutex_;        // 互斥锁，保证线程安全
};

// 方便使用的宏定义
#define LOG_DEBUG(message) tn_loam::Logger::getInstance().debug(message)
#define LOG_INFO(message) tn_loam::Logger::getInstance().info(message)
#define LOG_WARN(message) tn_loam::Logger::getInstance().warn(message)
#define LOG_ERROR(message) tn_loam::Logger::getInstance().error(message)
#define LOG_FATAL(message) tn_loam::Logger::getInstance().fatal(message)

#define LOG_DEBUGF(...) tn_loam::Logger::getInstance().debugf(__VA_ARGS__)
#define LOG_INFOF(...) tn_loam::Logger::getInstance().infof(__VA_ARGS__)
#define LOG_WARNF(...) tn_loam::Logger::getInstance().warnf(__VA_ARGS__)
#define LOG_ERRORF(...) tn_loam::Logger::getInstance().errorf(__VA_ARGS__)
#define LOG_FATALF(...) tn_loam::Logger::getInstance().fatalf(__VA_ARGS__)

} // namespace tn_loam