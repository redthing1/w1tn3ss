#pragma once

#include <cstring>
#include <string>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <unistd.h>
#else
#include <unistd.h>
#endif

namespace w1::monitor::test_paths {

inline std::string executable_path() {
#if defined(_WIN32)
  char buffer[MAX_PATH] = {};
  const DWORD len = GetModuleFileNameA(nullptr, buffer, MAX_PATH);
  return len ? std::string(buffer, len) : std::string{};
#elif defined(__APPLE__)
  uint32_t size = 0;
  _NSGetExecutablePath(nullptr, &size);
  std::string path(size, '\0');
  if (_NSGetExecutablePath(path.data(), &size) != 0) {
    return {};
  }
  path.resize(std::strlen(path.c_str()));
  return path;
#else
  char buffer[4096] = {};
  const ssize_t len = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
  if (len <= 0) {
    return {};
  }
  buffer[len] = '\0';
  return std::string(buffer);
#endif
}

inline std::string directory_from_path(const std::string& path) {
  const size_t pos = path.find_last_of("/\\");
  if (pos == std::string::npos) {
    return ".";
  }
  return path.substr(0, pos);
}

inline std::string test_library_path(const char* name) {
  const auto exe_path = executable_path();
  const auto exe_dir = directory_from_path(exe_path);
#if defined(_WIN32)
  return exe_dir + "\\..\\libraries\\" + name;
#else
  return exe_dir + "/../libraries/" + name;
#endif
}

} // namespace w1::monitor::test_paths
