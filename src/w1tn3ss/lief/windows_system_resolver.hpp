#pragma once

#ifdef _WIN32

#include <string>
#include <optional>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <redlog.hpp>

namespace w1::lief {

// Rich symbol information structure for Windows
struct windows_symbol_info {
  std::string name;
  std::string demangled_name;
  uint64_t address;
  uint64_t size;
  uint64_t displacement;
  std::string module_name;
  bool is_function;
  bool is_exported;
};

/**
 * @brief resolves windows system library basenames to full system paths
 * @details windows-specific resolver that maps bare dll names (e.g., "ucrtbase.dll") 
 * to their full system paths (e.g., "C:\Windows\System32\ucrtbase.dll").
 * handles system32, syswow64, and windows directory search.
 */
class windows_system_resolver {
public:
  windows_system_resolver();

  /**
   * @brief resolve system library basename to full path
   * @param basename dll name like "ucrtbase.dll" or "KERNEL32.DLL"
   * @return full path if found in system directories, nullopt otherwise
   */
  std::optional<std::string> resolve_system_library(const std::string& basename) const;

  /**
   * @brief check if resolver is available
   * @return true if system directories are accessible
   */
  bool is_available() const { return !system_directories_.empty(); }

  /**
   * @brief get list of configured system directories
   * @return vector of system directory paths
   */
  const std::vector<std::string>& get_system_directories() const { return system_directories_; }

private:
  std::vector<std::string> system_directories_;
  mutable redlog::logger log_;

  // cache for resolved paths to avoid repeated filesystem access
  mutable std::unordered_map<std::string, std::string> path_cache_;
  mutable std::mutex cache_mutex_;

  /**
   * @brief discover windows system directories using win32 apis
   * @return vector of system directory paths
   */
  std::vector<std::string> discover_system_directories() const;

  /**
   * @brief search for basename in system directories
   * @param basename dll filename to search for
   * @return full path if found, nullopt otherwise
   */
  std::optional<std::string> find_in_system_directories(const std::string& basename) const;

  /**
   * @brief normalize basename for consistent caching
   * @param basename original basename
   * @return normalized basename (lowercase, consistent format)
   */
  std::string normalize_basename(const std::string& basename) const;

  /**
   * @brief check if basename is a likely system library
   * @param basename dll filename
   * @return true if likely system library based on name patterns
   */
  bool is_likely_system_library(const std::string& basename) const;

  /**
   * @brief resolve symbol using Windows SymFromAddr API
   * @param address absolute address to resolve
   * @return symbol name if found, nullopt otherwise
   */
  std::optional<std::string> resolve_symbol_native(uint64_t address) const;

  /**
   * @brief resolve rich symbol information using Windows SymFromAddr API
   * @param address absolute address to resolve
   * @return detailed symbol information if found, nullopt otherwise
   */
  std::optional<windows_symbol_info> resolve_symbol_info_native(uint64_t address) const;
};

} // namespace w1::lief

#endif // _WIN32