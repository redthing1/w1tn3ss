#pragma once

#include "module_info.hpp"
#include "module_scanner.hpp"
#include "module_range_index.hpp"
#include <vector>
#include <functional>
#include <shared_mutex>
#include <QBDI.h>
#include <redlog.hpp>

namespace w1 {
namespace util {

/**
 * @brief facade for module discovery using new component architecture
 * @details coordinates module_scanner and module_range_index to provide
 * unified interface while maintaining backward compatibility.
 */
class module_discovery {
public:
  module_discovery();

  /**
   * @brief rescan modules and rebuild index
   * @details uses module_scanner to discover current modules and rebuilds
   * the fast lookup index. thread-safe operation.
   */
  void take_snapshot();

  /**
   * @brief find module containing the given address
   * @param address memory address to query
   * @return pointer to module_info if found, nullptr otherwise
   */
  const module_info* find_containing(QBDI::rword address) const;

  /**
   * @brief visit module containing address using visitor pattern
   * @param address memory address to query
   * @param visitor callable invoked with const module_info& if found
   * @return true if module found and visitor called, false otherwise
   */
  template <typename Visitor> bool visit_containing(QBDI::rword address, Visitor&& visitor) const;

  /**
   * @brief find module by name
   * @param name module name to search for
   * @return pointer to module_info if found, nullptr otherwise
   */
  const module_info* find_by_name(const std::string& name) const;

  /**
   * @brief get modules matching filter predicate
   * @param filter optional predicate function, nullptr means all modules
   * @return vector of matching modules
   */
  std::vector<module_info> get_modules(std::function<bool(const module_info&)> filter = nullptr) const;

  /**
   * @brief get user (non-system) modules
   * @return vector of user modules
   */
  std::vector<module_info> get_user_modules() const;

private:
  module_scanner scanner_;
  module_range_index index_;
  mutable std::shared_mutex mutex_;
  redlog::logger log_ = redlog::get_logger("w1.module_discovery");
};

template <typename Visitor> bool module_discovery::visit_containing(QBDI::rword address, Visitor&& visitor) const {
  std::shared_lock<std::shared_mutex> lock(mutex_);
  return index_.visit_containing(address, std::forward<Visitor>(visitor));
}

} // namespace util
} // namespace w1