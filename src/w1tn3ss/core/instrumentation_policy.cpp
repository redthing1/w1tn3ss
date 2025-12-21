#include "w1tn3ss/core/instrumentation_policy.hpp"

#include <algorithm>
#include <string_view>

namespace w1::core {
namespace {

std::vector<std::string> default_exclude_modules() {
#ifdef __APPLE__
  return {
      "libQBDI",
      "qbdipreload",
      "libsystem_malloc",
      "libsystem_c",
      "libsystem_kernel",
      "libsystem_pthread",
      "libsystem_platform",
      "libobjc"
  };
#elif defined(__linux__)
  return {
      "libQBDI",
      "qbdipreload",
      "libc-2.",
      "libc.so.",
      "ld-2.",
      "ld-linux",
      "libpthread-",
      "libcofi",
      "libdl",
      "librt"
  };
#elif defined(_WIN32)
  return {
      "QBDI",
      "qbdipreload",
      "advapi",
      "combase",
      "comctl32",
      "comdlg",
      "gdi32",
      "gdiplus",
      "imm32",
      "kernel",
      "msvcp",
      "msvcrt",
      "ntdll",
      "ole32",
      "oleaut",
      "rpcrt",
      "sechost",
      "shcore",
      "shell32",
      "shlwapi",
      "ucrtbase",
      "user32",
      "uxtheme",
      "vcruntime",
      "win32u"
  };
#else
  return {};
#endif
}

std::vector<std::string> critical_system_modules() {
#ifdef __APPLE__
  return {
      "libSystem",
      "libdispatch",
      "libc++",
      "libc++abi",
      "libdyld",
      "dyld"
  };
#elif defined(__linux__)
  return {
      "ld-linux",
      "ld-2.",
      "libc.so.",
      "libpthread",
      "libdl",
      "librt"
  };
#elif defined(_WIN32)
  return {
      "ntdll",
      "kernel",
      "kernel32",
      "user32"
  };
#else
  return {};
#endif
}

bool matches_any(std::string_view name, std::string_view path, const std::vector<std::string>& patterns) {
  for (const auto& pattern : patterns) {
    if (!pattern.empty() && (name.find(pattern) != std::string_view::npos || path.find(pattern) != std::string_view::npos)) {
      return true;
    }
  }
  return false;
}

} // namespace

bool instrumentation_policy::should_instrument(const runtime::module_info& module) const {
  std::string_view name = module.name;
  std::string_view path = module.path;

  if (!include_unnamed_modules && name.rfind("_unnamed_", 0) == 0) {
    return false;
  }

  if (use_default_excludes && matches_any(name, path, default_exclude_modules())) {
    return false;
  }

  if (!exclude_modules.empty() && matches_any(name, path, exclude_modules)) {
    return false;
  }

  if (!include_modules.empty() && !matches_any(name, path, include_modules)) {
    return false;
  }

  if (module.is_system) {
    switch (system_policy) {
    case system_module_policy::exclude_all:
      return false;
    case system_module_policy::include_critical:
      return matches_any(name, path, critical_system_modules());
    case system_module_policy::include_all:
      return true;
    default:
      return false;
    }
  }

  return true;
}

} // namespace w1::core
