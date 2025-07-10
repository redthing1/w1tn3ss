#pragma once

#ifdef _WIN32

#include "symbol_backend.hpp"
#include "symbol_info.hpp"
#include <redlog.hpp>
#include <mutex>
#include <unordered_map>
// forward declarations to avoid including windows headers in header
#ifdef _WIN32
struct _SYMBOL_INFO;
typedef _SYMBOL_INFO* PSYMBOL_INFO;
typedef unsigned long ULONG;
typedef void* PVOID;
typedef int BOOL;
// use void* for HMODULE to avoid windows.h dependency, we'll cast it later'
typedef void* ModuleHandle;
#endif

namespace w1::symbols {

/**
 * @brief windows native symbol resolution using DbgHelp APIs
 */
class windows_symbol_backend : public symbol_backend {
public:
  windows_symbol_backend();
  ~windows_symbol_backend();

  // symbol_backend interface
  std::optional<symbol_info> resolve_address(uint64_t address) const override;
  std::optional<uint64_t> resolve_name(const std::string& name, const std::string& module_hint = "") const override;
  std::optional<symbol_info> resolve_in_module(const std::string& module_path, uint64_t offset) const override;
  std::vector<symbol_info> find_symbols(const std::string& pattern, const std::string& module_hint = "") const override;
  std::vector<symbol_info> get_module_symbols(const std::string& module_path) const override;

  std::string get_name() const override { return "windows_native"; }
  bool is_available() const override;
  capabilities get_capabilities() const override;
  void clear_cache() override;

private:
  // internal windows symbol info structure
  struct windows_symbol_info {
    std::string name;
    std::string demangled_name;
    std::string module_name;
    uint64_t address;
    uint64_t size;
    uint64_t displacement;
    bool is_function;
    bool is_exported;
  };

  // helper methods
  std::optional<windows_symbol_info> resolve_symbol_info_native(uint64_t address) const;
  symbol_info convert_to_symbol_info(const windows_symbol_info& win_info) const;
  ModuleHandle get_module_handle_safe(const std::string& module_name) const;

  // symbol enumeration callback (implementation in cpp)
  static BOOL __stdcall enum_symbols_callback(PSYMBOL_INFO symbol_info, ULONG symbol_size, PVOID user_context);

  // logging
  mutable redlog::logger log_;

  // initialization tracking
  static std::once_flag init_flag_;
  static bool init_success_;

  // cache for module handles
  mutable std::mutex cache_mutex_;
  mutable std::unordered_map<std::string, ModuleHandle> module_cache_;
};

} // namespace w1::symbols

#endif // _WIN32