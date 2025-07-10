#pragma once

#include <optional>
#include <string>
#include <vector>

namespace w1::symbols {

/**
 * @brief abstract interface for platform-specific path resolution
 *
 * resolves library names to full paths on the filesystem.
 * handles system libraries, dyld cache, and other platform quirks.
 */
class path_resolver {
public:
  virtual ~path_resolver() = default;

  /**
   * @brief resolve library name to full path
   * @param library_name name or partial path (e.g. "kernel32.dll", "libc.so.6")
   * @return full path if found
   */
  virtual std::optional<std::string> resolve_library_path(const std::string& library_name) const = 0;

  /**
   * @brief get system library directories
   * @return list of directories where system libraries are located
   */
  virtual std::vector<std::string> get_system_directories() const = 0;

  /**
   * @brief check if path is likely a system library
   * @param path library path or name
   * @return true if this appears to be a system library
   */
  virtual bool is_system_library(const std::string& path) const = 0;

  /**
   * @brief get resolver name for debugging
   * @return resolver identifier (e.g. "windows_path", "macos_dyld", "linux_ldso")
   */
  virtual std::string get_name() const = 0;
};

} // namespace w1::symbols