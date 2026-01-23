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

enum class module_match_mode {
  auto_detect,
  basename,
  full_path,
};

inline bool has_path_separator(std::string_view value) {
  return value.find('/') != std::string_view::npos || value.find('\\') != std::string_view::npos;
}

inline module_match_mode normalize_match_mode(std::string_view requested, module_match_mode mode) {
  if (mode == module_match_mode::auto_detect) {
    return has_path_separator(requested) ? module_match_mode::full_path : module_match_mode::basename;
  }
  return mode;
}

#if defined(_WIN32)
inline std::string to_lower(std::string_view value) {
  std::string out(value.begin(), value.end());
  for (auto& ch : out) {
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  }
  return out;
}

inline bool module_matches(const char* requested,
                           std::string_view path,
                           module_match_mode mode = module_match_mode::auto_detect) {
  if (!requested || requested[0] == '\0') {
    return true;
  }
  if (path.empty()) {
    return false;
  }
  const std::string req_lower = to_lower(requested);
  const std::string full_lower = to_lower(path);
  const auto match_mode = normalize_match_mode(std::string_view(requested), mode);
  if (match_mode == module_match_mode::full_path) {
    return full_lower == req_lower;
  }
  const std::string_view base = basename_view(full_lower);
  return base == std::string_view(req_lower);
}
#else
inline bool module_matches(const char* requested,
                           std::string_view path,
                           module_match_mode mode = module_match_mode::auto_detect) {
  if (!requested || requested[0] == '\0') {
    return true;
  }
  if (path.empty()) {
    return false;
  }
  const std::string_view req_view(requested);
  const auto match_mode = normalize_match_mode(req_view, mode);
  if (match_mode == module_match_mode::full_path) {
    return path == req_view;
  }
  return basename_view(path) == basename_view(req_view);
}
#endif

} // namespace w1::h00k::resolve
