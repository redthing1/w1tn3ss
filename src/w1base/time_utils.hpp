#pragma once

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>

namespace w1::util {

inline std::string format_timestamp_local_ms(uint64_t ms_since_epoch, const char* format = "%Y-%m-%d %H:%M:%S") {
  auto duration = std::chrono::milliseconds(ms_since_epoch);
  auto tp = std::chrono::system_clock::time_point(duration);
  auto time_t = std::chrono::system_clock::to_time_t(tp);

  std::stringstream ss;
  ss << std::put_time(std::localtime(&time_t), format);
  return ss.str();
}

inline std::string format_timestamp_utc_iso8601_ms(
    std::chrono::system_clock::time_point tp = std::chrono::system_clock::now()
) {
  auto time_t = std::chrono::system_clock::to_time_t(tp);
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()) % 1000;

  std::stringstream ss;
  ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%S");
  ss << '.' << std::setfill('0') << std::setw(3) << ms.count() << 'Z';
  return ss.str();
}

} // namespace w1::util
