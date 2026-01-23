#pragma once

#include <string>
#include <cwchar>

#include <windows.h>

namespace w1::monitor::backend::windows {

inline std::string utf16_to_utf8(const wchar_t* value, size_t length) {
  if (!value || length == 0) {
    return {};
  }
  const int wchar_len = static_cast<int>(length);
  if (wchar_len <= 0) {
    return {};
  }
  const int required = WideCharToMultiByte(CP_UTF8, 0, value, wchar_len, nullptr, 0, nullptr, nullptr);
  if (required <= 0) {
    return {};
  }
  std::string out(static_cast<size_t>(required), '\0');
  WideCharToMultiByte(CP_UTF8, 0, value, wchar_len, out.data(), required, nullptr, nullptr);
  return out;
}

inline std::string utf16_to_utf8(const UNICODE_STRING* value) {
  if (!value || !value->Buffer || value->Length == 0) {
    return {};
  }
  const size_t wchar_len = static_cast<size_t>(value->Length / sizeof(WCHAR));
  return utf16_to_utf8(value->Buffer, wchar_len);
}

inline std::string utf16_to_utf8(PCWSTR value) {
  if (!value) {
    return {};
  }
  const size_t wchar_len = std::wcslen(value);
  return utf16_to_utf8(value, wchar_len);
}

} // namespace w1::monitor::backend::windows
