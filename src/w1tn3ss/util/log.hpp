#pragma once

#include <string>

namespace w1::util {

void log_msg(const std::string& message);
void log_debug(const std::string& message);
void log_trace(const std::string& message);
void log_info(const std::string& message);
void log_warn(const std::string& message);
void log_error(const std::string& message);

} // namespace w1::util

static inline void ensure(bool condition, const std::string& message) {
  if (!condition) {
    w1::util::log_error("assertion failed: " + message);
    throw std::runtime_error("assertion failed: " + message);
  }
}

#define ENSURE(condition, message) ensure(condition, message)