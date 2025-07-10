#pragma once

#include "symbol_info.hpp"
#include <optional>
#include <string>
#include <vector>
#include <cstdint>

namespace w1::symbols {

/**
 * @brief abstract interface for symbol resolution backends
 *
 * defines the contract that all symbol resolution implementations must follow.
 * backends can use native APIs, LIEF, or other methods to resolve symbols.
 */
class symbol_backend {
public:
  virtual ~symbol_backend() = default;

  // core resolution methods

  /**
   * @brief resolve symbol at absolute address
   * @param address absolute memory address
   * @return symbol information if found
   */
  virtual std::optional<symbol_info> resolve_address(uint64_t address) const = 0;

  /**
   * @brief resolve symbol address by name
   * @param name symbol name to look up
   * @param module_hint optional module to search in (empty = search all)
   * @return absolute address if found
   */
  virtual std::optional<uint64_t> resolve_name(const std::string& name, const std::string& module_hint = "") const = 0;

  /**
   * @brief resolve symbol in specific module at offset
   * @param module_path path to module
   * @param offset offset within module
   * @return symbol information if found
   */
  virtual std::optional<symbol_info> resolve_in_module(const std::string& module_path, uint64_t offset) const = 0;

  /**
   * @brief find symbols matching pattern
   * @param pattern wildcard pattern (e.g. "malloc*", "*printf")
   * @param module_hint optional module to search in
   * @return matching symbols
   */
  virtual std::vector<symbol_info> find_symbols(
      const std::string& pattern, const std::string& module_hint = ""
  ) const = 0;

  /**
   * @brief get all symbols from a module
   * @param module_path path to module
   * @return all symbols in module
   */
  virtual std::vector<symbol_info> get_module_symbols(const std::string& module_path) const = 0;

  // backend information

  /**
   * @brief get backend name for debugging
   * @return backend identifier (e.g. "windows_native", "lief", "posix_native")
   */
  virtual std::string get_name() const = 0;

  /**
   * @brief check if backend is available on current platform
   * @return true if backend can be used
   */
  virtual bool is_available() const = 0;

  /**
   * @brief get capabilities of this backend
   */
  struct capabilities {
    bool supports_runtime_resolution; // can resolve from running process
    bool supports_file_resolution;    // can resolve from file on disk
    bool supports_pattern_matching;   // supports wildcard patterns
    bool supports_demangling;         // can demangle C++ names
  };

  virtual capabilities get_capabilities() const = 0;

  // cache management

  /**
   * @brief clear any internal caches
   */
  virtual void clear_cache() = 0;
};

} // namespace w1::symbols