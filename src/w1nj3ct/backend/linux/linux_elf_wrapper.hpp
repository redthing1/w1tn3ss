#pragma once

#include "linux_elf.h"
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace w1::inject::linux_elf {

// RAII wrapper for memory maps
class memory_maps {
public:
  memory_maps() = default;
  ~memory_maps() { reset(); }

  // non-copyable but movable
  memory_maps(const memory_maps&) = delete;
  memory_maps& operator=(const memory_maps&) = delete;
  memory_maps(memory_maps&& other) noexcept : maps_(other.maps_), count_(other.count_) {
    other.maps_ = nullptr;
    other.count_ = 0;
  }
  memory_maps& operator=(memory_maps&& other) noexcept {
    if (this != &other) {
      reset();
      maps_ = other.maps_;
      count_ = other.count_;
      other.maps_ = nullptr;
      other.count_ = 0;
    }
    return *this;
  }

  bool load(pid_t pid) {
    reset();
    return linux_parse_proc_maps(pid, &maps_, &count_) == LINUX_ELF_SUCCESS;
  }

  size_t size() const { return count_; }
  bool empty() const { return count_ == 0; }

  const linux_memory_map_t* data() const { return maps_; }
  const linux_memory_map_t& operator[](size_t index) const { return maps_[index]; }

  // iterator support
  const linux_memory_map_t* begin() const { return maps_; }
  const linux_memory_map_t* end() const { return maps_ + count_; }

private:
  void reset() {
    if (maps_) {
      linux_free_memory_maps(maps_, count_);
      maps_ = nullptr;
      count_ = 0;
    }
  }

  linux_memory_map_t* maps_ = nullptr;
  size_t count_ = 0;
};

// RAII wrapper for symbols
class symbol_list {
public:
  symbol_list() = default;
  ~symbol_list() { reset(); }

  // non-copyable but movable
  symbol_list(const symbol_list&) = delete;
  symbol_list& operator=(const symbol_list&) = delete;
  symbol_list(symbol_list&& other) noexcept : symbols_(other.symbols_), count_(other.count_) {
    other.symbols_ = nullptr;
    other.count_ = 0;
  }
  symbol_list& operator=(symbol_list&& other) noexcept {
    if (this != &other) {
      reset();
      symbols_ = other.symbols_;
      count_ = other.count_;
      other.symbols_ = nullptr;
      other.count_ = 0;
    }
    return *this;
  }

  bool load(pid_t pid, const std::string& lib_name) {
    reset();
    return linux_find_all_symbols(pid, lib_name.c_str(), &symbols_, &count_) == LINUX_ELF_SUCCESS;
  }

  size_t size() const { return count_; }
  bool empty() const { return count_ == 0; }

  const linux_symbol_t* data() const { return symbols_; }
  const linux_symbol_t& operator[](size_t index) const { return symbols_[index]; }

  // iterator support
  const linux_symbol_t* begin() const { return symbols_; }
  const linux_symbol_t* end() const { return symbols_ + count_; }

private:
  void reset() {
    if (symbols_) {
      linux_free_symbols(symbols_, count_);
      symbols_ = nullptr;
      count_ = 0;
    }
  }

  linux_symbol_t* symbols_ = nullptr;
  size_t count_ = 0;
};

// RAII wrapper for modules
class module_list {
public:
  module_list() = default;
  ~module_list() { reset(); }

  // non-copyable but movable
  module_list(const module_list&) = delete;
  module_list& operator=(const module_list&) = delete;
  module_list(module_list&& other) noexcept : modules_(other.modules_), count_(other.count_) {
    other.modules_ = nullptr;
    other.count_ = 0;
  }
  module_list& operator=(module_list&& other) noexcept {
    if (this != &other) {
      reset();
      modules_ = other.modules_;
      count_ = other.count_;
      other.modules_ = nullptr;
      other.count_ = 0;
    }
    return *this;
  }

  bool load(pid_t pid) {
    reset();
    return linux_get_loaded_modules(pid, &modules_, &count_) == LINUX_ELF_SUCCESS;
  }

  size_t size() const { return count_; }
  bool empty() const { return count_ == 0; }

  const linux_module_t* data() const { return modules_; }
  const linux_module_t& operator[](size_t index) const { return modules_[index]; }

  // iterator support
  const linux_module_t* begin() const { return modules_; }
  const linux_module_t* end() const { return modules_ + count_; }

private:
  void reset() {
    if (modules_) {
      linux_free_modules(modules_, count_);
      modules_ = nullptr;
      count_ = 0;
    }
  }

  linux_module_t* modules_ = nullptr;
  size_t count_ = 0;
};

// High-level C++ interface
class elf_resolver {
public:
  explicit elf_resolver(pid_t pid) : pid_(pid) {}

  // find library base address
  std::optional<void*> find_library_base(const std::string& lib_name) const {
    void* base_addr = nullptr;
    if (linux_find_library_base(pid_, lib_name.c_str(), &base_addr) == LINUX_ELF_SUCCESS) {
      return base_addr;
    }
    return std::nullopt;
  }

  // find symbol address
  std::optional<void*> find_symbol(const std::string& lib_name, const std::string& symbol_name) const {
    void* symbol_addr = nullptr;
    if (linux_find_symbol(pid_, lib_name.c_str(), symbol_name.c_str(), &symbol_addr) == LINUX_ELF_SUCCESS) {
      return symbol_addr;
    }
    return std::nullopt;
  }

  // get process memory maps
  memory_maps get_memory_maps() const {
    memory_maps maps;
    maps.load(pid_);
    return maps;
  }

  // get all symbols from library
  symbol_list get_symbols(const std::string& lib_name) const {
    symbol_list symbols;
    symbols.load(pid_, lib_name);
    return symbols;
  }

  // get all loaded modules
  module_list get_modules() const {
    module_list modules;
    modules.load(pid_);
    return modules;
  }

  // resolve address to symbol
  std::optional<linux_symbol_t> resolve_address(void* address) const {
    linux_symbol_t symbol;
    if (linux_resolve_symbol_by_address(pid_, address, &symbol) == LINUX_ELF_SUCCESS) {
      return symbol;
    }
    return std::nullopt;
  }

  // check if process is 64-bit
  std::optional<bool> is_64bit() const {
    int is_64 = 0;
    if (linux_get_process_arch(pid_, &is_64) == LINUX_ELF_SUCCESS) {
      return is_64 != 0;
    }
    return std::nullopt;
  }

  pid_t get_pid() const { return pid_; }

private:
  pid_t pid_;
};

// convenience functions
inline std::optional<void*> find_symbol(pid_t pid, const std::string& lib_name, const std::string& symbol_name) {
  return elf_resolver(pid).find_symbol(lib_name, symbol_name);
}

inline std::optional<void*> find_library_base(pid_t pid, const std::string& lib_name) {
  return elf_resolver(pid).find_library_base(lib_name);
}

inline bool is_elf_file(const std::string& path) { return linux_is_elf_file(path.c_str()) != 0; }

inline std::string error_string(int error_code) { return linux_elf_error_string(error_code); }

} // namespace w1::inject::linux_elf