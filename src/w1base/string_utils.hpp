#pragma once

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>

namespace w1::util {

inline std::string to_lower(std::string_view value) {
  std::string out(value.begin(), value.end());
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return out;
}

inline std::string_view trim_view(std::string_view value) {
  size_t first = value.find_first_not_of(' ');
  if (first == std::string_view::npos) {
    return value;
  }
  size_t last = value.find_last_not_of(' ');
  return value.substr(first, last - first + 1);
}

inline std::string trim_copy(std::string_view value) {
  std::string_view trimmed = trim_view(value);
  return std::string(trimmed.begin(), trimmed.end());
}

} // namespace w1::util
