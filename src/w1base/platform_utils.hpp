#pragma once

#include <string>
#include <vector>

#ifdef _WIN32
#define NEED_PSAPI
#define NEED_TLHELP32
#include <w1base/windows_clean.hpp>
#endif

namespace w1::common {

/**
 * @brief Cross-platform utility functions for platform detection and path handling
 */
namespace platform_utils {

/**
 * @brief Get the current platform name as a string
 * @return Platform name ("darwin", "linux", "windows", or "unknown")
 */
inline std::string get_platform_name() {
#ifdef __APPLE__
  return "darwin";
#elif defined(__linux__)
  return "linux";
#elif defined(_WIN32)
  return "windows";
#else
  return "unknown";
#endif
}

/**
 * @brief Get the appropriate dynamic library file extension for the current platform
 * @return Library extension including the dot (e.g., ".dylib", ".so", ".dll")
 */
inline std::string get_library_extension() {
#ifdef __APPLE__
  return ".dylib";
#elif defined(__linux__)
  return ".so";
#elif defined(_WIN32)
  return ".dll";
#else
#error "Unsupported platform for dynamic library loading"
#endif
}

/**
 * @brief Get standard system library paths for the current platform
 * @return Vector of system library directory paths
 */
inline std::vector<std::string> get_system_library_paths() {
  std::vector<std::string> paths;

#ifdef __APPLE__
  paths = {"/System/Library/", "/usr/lib/", "/usr/local/lib/", "/Library/Frameworks/"};
#elif defined(__linux__)
  paths = {
      "/lib/",
      "/lib64/",
      "/usr/lib/",
      "/usr/lib64/",
      "/usr/local/lib/",
      "/usr/lib/x86_64-linux-gnu/",
      "/lib/x86_64-linux-gnu/"
  };
#elif defined(_WIN32)
  paths = {"C:\\Windows\\System32\\", "C:\\Windows\\SysWOW64\\", "C:\\Program Files\\", "C:\\Program Files (x86)\\"};
#endif

  return paths;
}

/**
 * @brief Check if a given path represents a system library/module
 * @param path The path to check
 * @return True if the path appears to be a system library
 */
inline bool is_system_library_path(const std::string& path) {
  if (path.empty() || path == "[anonymous]" || path.find("[") == 0) {
    return true; // anonymous mappings are usually system
  }

  auto system_paths = get_system_library_paths();
  for (const auto& sys_path : system_paths) {
    if (path.find(sys_path) != std::string::npos) {
      return true;
    }
  }

  // check for common system library name patterns
#ifdef __APPLE__
  return path.find("libsystem_") != std::string::npos || path.find("libc++") != std::string::npos ||
         path.find("libdyld") != std::string::npos || path.find(".framework/") != std::string::npos;
#elif defined(__linux__)
  return path.find("ld-linux") != std::string::npos || path.find("libc.so") != std::string::npos ||
         path.find("libstdc++") != std::string::npos || path.find("libgcc") != std::string::npos;
#elif defined(_WIN32)
  return path.find("ntdll.dll") != std::string::npos || path.find("kernel32.dll") != std::string::npos ||
         path.find("msvcrt.dll") != std::string::npos || path.find("vcruntime") != std::string::npos;
#else
  return false;
#endif
}

/**
 * @brief Get the platform-specific process ID type size
 * @return Size of process ID in bytes
 */
inline size_t get_pid_size() {
#ifdef _WIN32
  return sizeof(DWORD);
#else
  return sizeof(pid_t);
#endif
}

/**
 * @brief Check if the current platform supports runtime library injection
 * @return True if runtime injection is supported
 */
inline bool supports_runtime_injection() {
#ifdef __APPLE__
  return true; // DYLD_INSERT_LIBRARIES
#elif defined(__linux__)
  return true; // LD_PRELOAD
#elif defined(_WIN32)
  return true; // DLL injection via CreateRemoteThread/SetWindowsHookEx
#else
  return false;
#endif
}

/**
 * @brief Get the environment variable name for library preloading
 * @return Environment variable name for the current platform
 */
inline std::string get_preload_env_var() {
#ifdef __APPLE__
  return "DYLD_INSERT_LIBRARIES";
#elif defined(__linux__)
  return "LD_PRELOAD";
#elif defined(_WIN32)
  return ""; // windows doesn't use environment variables for DLL injection
#else
  return "";
#endif
}

} // namespace platform_utils
} // namespace w1::common