#pragma once

#include "module_info.hpp"
#include <vector>
#include <unordered_set>
#include <functional>
#include <QBDI.h>
#include <redlog/redlog.hpp>

namespace w1 {
namespace util {

/**
 * @brief stateless utility for discovering modules from system memory maps
 * @details handles platform-specific qbdi interaction and module classification.
 * thread-safe for concurrent use. no internal state maintained.
 */
class module_scanner {
public:
  module_scanner();

  /**
   * @brief scan all executable modules from current process
   * @return vector of discovered executable modules
   */
  std::vector<module_info> scan_executable_modules();

  /**
   * @brief scan only user (non-system) executable modules
   * @return vector of user modules, filtered by platform-specific heuristics
   */
  std::vector<module_info> scan_user_modules() const;

  /**
   * @brief incremental scan for modules not in known set
   * @param known_bases set of already-known module base addresses
   * @return vector of newly discovered modules
   * @details useful for rescanning without full discovery overhead
   */
  std::vector<module_info> scan_new_modules(const std::unordered_set<QBDI::rword>& known_bases);

private:
  redlog::logger log_ = redlog::get_logger("w1.module_scanner");

  // platform-specific helpers
  std::vector<QBDI::MemoryMap> get_executable_maps();
  module_info build_module_info(const QBDI::MemoryMap& map);
  module_type classify_module(const QBDI::MemoryMap& map) const;
  bool is_system_library(const std::string& path) const;
  std::string extract_basename(const std::string& path) const;
};

} // namespace util
} // namespace w1