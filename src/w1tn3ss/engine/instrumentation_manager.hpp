#pragma once

#include <QBDI.h>
#include <redlog.hpp>
#include <memory>
#include <unordered_set>

#include "instrumentation_config.hpp"
#include "instrumentation_lists.hpp"
#include <w1tn3ss/util/module_scanner.hpp>

namespace w1 {

/**
 * manages instrumentation ranges for a qbdi vm based on configuration
 * handles both preload (remove unwanted) and fresh (add wanted) scenarios
 */
class instrumentation_manager {
public:
  explicit instrumentation_manager(const instrumentation_config& config);

  /**
   * apply instrumentation configuration to a vm
   * always starts fresh by removing all existing instrumentation first
   * @param vm the qbdi vm instance
   * @return true if successful
   */
  bool apply_instrumentation(QBDI::VM* vm);

  /**
   * check if a specific module should be instrumented based on config
   * @param module_info the module to check
   * @return true if the module should be instrumented
   */
  bool should_instrument_module(const util::module_info& module) const;

private:
  const instrumentation_config& config_;
  mutable redlog::logger log_{"w1.instrumentation_manager"};

  /**
   * configure instrumentation by adding only the modules we want
   */
  bool configure_instrumentation(QBDI::VM* vm, const std::vector<util::module_info>& modules);
};

} // namespace w1