#pragma once

#include <cctype>
#include <string>
#include <string_view>

namespace w1::h00k::resolve {

inline std::string_view basename_view(std::string_view path) {
  const size_t pos = path.find_last_of("/\\");
  if (pos == std::string_view::npos) {
    return path;
  }
  return path.substr(pos + 1);
}

#if defined(_WIN32)
inline std::string to_lower(std::string_view value) {
  std::string out(value.begin(), value.end());
  for (auto& ch : out) {
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  }
  return out;
}

inline bool module_matches(const char* requested, const std::string& path) {
  if (!requested || requested[0] == '\0') {
    return true;
  }
  if (path.empty()) {
    return false;
  }
  const std::string req = to_lower(requested);
  const std::string full = to_lower(path);
  const bool has_sep = req.find('/') != std::string::npos || req.find('\\') != std::string::npos;
  if (has_sep) {
    return full == req;
  }
  return to_lower(std::string(basename_view(full))) == req;
}
#else
inline bool module_matches(const char* requested, const std::string& path) {
  if (!requested || requested[0] == '\0') {
    return true;
  }
  if (path.empty()) {
    return false;
  }
  const std::string_view req_view(requested);
  const bool has_sep = req_view.find('/') != std::string_view::npos ||
                       req_view.find('\\') != std::string_view::npos;
  if (has_sep) {
    return path == requested;
  }
  return basename_view(path) == req_view;
}
#endif

} // namespace w1::h00k::resolve
