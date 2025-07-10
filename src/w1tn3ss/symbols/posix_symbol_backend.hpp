#pragma once

#if !defined(_WIN32)

#include "symbol_backend.hpp"
#include "symbol_info.hpp"
#include <redlog.hpp>
#include <mutex>
#include <unordered_map>

namespace w1::symbols {

/**
 * @brief posix native symbol resolution using dladdr/dlsym
 *
 * provides runtime symbol resolution for unix-like systems
 * (linux, macos, bsd, etc.) using standard posix APIs.
 */
class posix_symbol_backend : public symbol_backend {
public:
  posix_symbol_backend();
  ~posix_symbol_backend();

  // symbol_backend interface
  std::optional<symbol_info> resolve_address(uint64_t address) const override;
  std::optional<uint64_t> resolve_name(const std::string& name, const std::string& module_hint = "") const override;
  std::optional<symbol_info> resolve_in_module(const std::string& module_path, uint64_t offset) const override;
  std::vector<symbol_info> find_symbols(const std::string& pattern, const std::string& module_hint = "") const override;
  std::vector<symbol_info> get_module_symbols(const std::string& module_path) const override;

  std::string get_name() const override { return "posix_native"; }
  bool is_available() const override { return true; }
  capabilities get_capabilities() const override;
  void clear_cache() override;

private:
  // helper to open a module handle
  void* open_module(const std::string& module_path) const;

  // helper to convert dladdr info to symbol_info
  symbol_info dladdr_to_symbol_info(const void* addr_info, uint64_t query_address) const;

  // cache for module handles
  mutable std::mutex cache_mutex_;
  mutable std::unordered_map<std::string, void*> handle_cache_;

  // logging
  redlog::logger log_;
};

} // namespace w1::symbols

#endif // !_WIN32