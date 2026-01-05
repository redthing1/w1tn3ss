#pragma once

#include <string>
#include <utility>

namespace p1ll::engine {

// engine error codes for structured results
enum class error_code {
  ok,
  invalid_argument,
  invalid_pattern,
  not_found,
  multiple_matches,
  io_error,
  protection_error,
  verification_failed,
  platform_mismatch,
  overlap,
  unsupported,
  invalid_context,
  internal_error
};

// status holds an error code and a human-readable message
struct status {
  error_code code = error_code::ok;
  std::string message;

  bool ok() const noexcept { return code == error_code::ok; }
};

inline status ok_status() { return {}; }

inline status make_status(error_code code, std::string message) { return status{code, std::move(message)}; }

// result carries a value and a status; value is default-initialized on errors
template <typename T> struct result {
  T value{};
  status status{};

  bool ok() const noexcept { return status.ok(); }
};

template <typename T> inline result<T> ok_result(T value) { return result<T>{std::move(value), ok_status()}; }

template <typename T> inline result<T> error_result(error_code code, std::string message) {
  return result<T>{T{}, make_status(code, std::move(message))};
}

} // namespace p1ll::engine
