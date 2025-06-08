#include "log.hpp"
#include <iostream>

// Simple colored output - can be enhanced later with proper color library
namespace w1::util {

void log_msg(const std::string& message) {
  std::cout << message << std::endl;
}

void log_debug(const std::string& message) {
  std::cout << "[dbg] " << message << std::endl;
}

void log_trace(const std::string& message) {
  std::cout << "[trc] " << message << std::endl;
}

void log_info(const std::string& message) {
  std::cout << "[inf] " << message << std::endl;
}

void log_warn(const std::string& message) {
  std::cout << "[wrn] " << message << std::endl;
}

void log_error(const std::string& message) {
  std::cout << "[err] " << message << std::endl;
}

} // namespace w1::util