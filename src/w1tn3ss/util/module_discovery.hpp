#pragma once

#include "module_info.hpp"
#include <vector>
#include <functional>
#include <shared_mutex>
#include <map>
#include <unordered_map>
#include <QBDI.h>
#include <redlog/redlog.hpp>

namespace w1 {
namespace util {

class module_discovery {
public:
  module_discovery();

  void take_snapshot();

  const module_info& get_module_for_address(QBDI::rword address) const;

  const module_info* find_module_by_name(const std::string& name) const;

  std::vector<module_info> get_modules(std::function<bool(const module_info&)> filter = nullptr) const;

  std::vector<module_info> get_user_modules() const;

private:
  mutable std::shared_mutex mutex_;
  redlog::logger log_ = redlog::get_logger("w1.module_discovery");

  std::map<QBDI::rword, module_info> address_map_;
  std::unordered_map<std::string, const module_info*> name_map_;

  static const module_info unknown_module_;

  void clear_internal_data();
  void populate_from_qbdi_maps();
  module_type classify_module(const QBDI::MemoryMap& map) const;
  bool is_system_library(const std::string& path) const;
  std::string extract_basename(const std::string& path) const;
};

} // namespace util
} // namespace w1