#pragma once

#include <exception>
#include <initializer_list>
#include <string>
#include <string_view>
#include <utility>

#include "w1base/string_utils.hpp"
#include "w1base/types.hpp"

namespace w1::util {

template <typename Enum>
bool parse_enum(std::string_view value, const std::initializer_list<std::pair<const char*, Enum>>& mapping, Enum& out) {
  std::string lower = to_lower(value);
  for (const auto& entry : mapping) {
    if (lower == to_lower(entry.first)) {
      out = entry.second;
      return true;
    }
  }
  return false;
}

inline bool parse_address_range(std::string_view text, w1::address_range& out, std::string* error) {
  auto set_error = [&](std::string message) {
    if (error) {
      *error = std::move(message);
    }
  };

  const size_t dash = text.find('-');
  if (dash == std::string_view::npos) {
    set_error("range must be in start-end form");
    return false;
  }

  std::string_view start_view = trim_view(text.substr(0, dash));
  std::string_view end_view = trim_view(text.substr(dash + 1));
  if (start_view.empty() || end_view.empty()) {
    set_error("range start/end missing");
    return false;
  }

  try {
    uint64_t start = std::stoull(std::string(start_view), nullptr, 0);
    uint64_t end = std::stoull(std::string(end_view), nullptr, 0);
    if (end <= start) {
      set_error("range end must be greater than start");
      return false;
    }
    out.start = start;
    out.end = end;
    return true;
  } catch (const std::exception& exc) {
    set_error(std::string("invalid range value: ") + exc.what());
    return false;
  }
}

} // namespace w1::util
