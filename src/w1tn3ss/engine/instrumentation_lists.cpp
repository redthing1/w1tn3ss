#include "instrumentation_lists.hpp"

namespace w1 {

std::vector<std::string> instrumentation_lists::get_conflict_modules() {
#ifdef __APPLE__
  return {
      // qbdi itself and preload libraries
      "libQBDI", "qbdipreload",

      // low-level system libraries that could cause recursion
      "libsystem_malloc", "libsystem_c", "libsystem_kernel", "libsystem_pthread", "libsystem_platform",

      // objc runtime (can cause issues with instrumentation)
      "libobjc"
  };
#elif defined(__linux__)
  return {
      // qbdi itself
      "libQBDI", "qbdipreload",

      // core system libraries from qbdi preload
      "libc-2.", "libc.so.", "ld-2.", "ld-linux", "libpthread-",

      // additional conflict libraries
      "libcofi", "libdl", "librt"
  };
#elif defined(_WIN32)
  return {
      // qbdi itself
      "QBDI", "qbdipreload",

      // windows system libraries from qbdi preload
      "advapi", "combase", "comctl32", "comdlg", "gdi32", "gdiplus", "imm32", "kernel", "msvcp", "msvcrt", "ntdll",
      "ole32", "oleaut", "rpcrt", "sechost", "shcore", "shell32", "shlwapi", "ucrtbase", "user32", "uxtheme",
      "vcruntime", "win32u"
  };
#else
  return {};
#endif
}

std::vector<std::string> instrumentation_lists::get_critical_modules() {
#ifdef __APPLE__
  return {
      "libdyld" // dynamic linker - critical for proper execution
  };
#elif defined(__linux__)
  return {
      // linux doesn't have critical modules in the same way
      // the dynamic linker is already excluded as a conflict module
  };
#elif defined(_WIN32)
  return {
      // windows doesn't require critical modules in the same way
  };
#else
  return {};
#endif
}

bool instrumentation_lists::matches_any(const std::string& module_name, const std::vector<std::string>& patterns) {
  return std::any_of(patterns.begin(), patterns.end(), [&module_name](const std::string& pattern) {
    return module_name.find(pattern) != std::string::npos;
  });
}

bool instrumentation_lists::is_conflict_module(const std::string& module_name) {
  static const auto conflict_modules = get_conflict_modules();
  return matches_any(module_name, conflict_modules);
}

bool instrumentation_lists::is_critical_module(const std::string& module_name) {
  static const auto critical_modules = get_critical_modules();
  return matches_any(module_name, critical_modules);
}

} // namespace w1