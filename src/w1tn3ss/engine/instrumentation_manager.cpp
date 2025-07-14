#include "instrumentation_manager.hpp"

namespace w1 {

instrumentation_manager::instrumentation_manager(const instrumentation_config& config) : config_(config) {}

bool instrumentation_manager::apply_instrumentation(QBDI::VM* vm) {
  if (!vm) {
    log_.err("cannot apply instrumentation to null vm");
    return false;
  }

  log_.inf("configuring instrumentation");

  // always start fresh - remove all existing instrumentation
  log_.trc("removing all existing instrumented ranges");
  vm->removeAllInstrumentedRanges();

  // scan current modules
  log_.trc("scanning executable modules");
  util::module_scanner scanner;
  auto modules = scanner.scan_executable_modules();

  log_.dbg("found executable modules", redlog::field("count", modules.size()));

  // now add only the modules we want
  return configure_instrumentation(vm, modules);
}

bool instrumentation_manager::should_instrument_module(const util::module_info& module) const {
  const std::string& name = module.name;

  log_.ped(
      "evaluating module", redlog::field("name", name), redlog::field("base", "0x%lx", module.base_address),
      redlog::field("is_system", module.is_system_library)
  );

  // step 1: exclude unnamed modules (runtime-generated code)
  if (name.starts_with("_unnamed_")) {
    log_.dbg("excluding unnamed module", redlog::field("name", name));
    return false;
  }

  // step 2: check conflict modules (never instrument)
  if (config_.use_default_conflicts && instrumentation_lists::is_conflict_module(name)) {
    log_.dbg("excluding conflict module", redlog::field("name", name));
    return false;
  }

  // step 3: check force exclude list
  if (!config_.force_exclude.empty() && instrumentation_lists::matches_any(name, config_.force_exclude)) {
    log_.dbg("excluding force-excluded module", redlog::field("name", name));
    return false;
  }

  // step 4: check critical modules (always instrument if using defaults)
  if (config_.use_default_criticals && instrumentation_lists::is_critical_module(name)) {
    log_.dbg("including critical module", redlog::field("name", name));
    return true;
  }

  // step 5: check force include list
  if (!config_.force_include.empty() && instrumentation_lists::matches_any(name, config_.force_include)) {
    log_.dbg("including force-included module", redlog::field("name", name));
    return true;
  }

  // step 6: apply module filter if specified
  if (!config_.module_filter.empty()) {
    bool matches = instrumentation_lists::matches_any(name, config_.module_filter);
    if (matches) {
      log_.dbg("including module (matches filter)", redlog::field("name", name));
    } else {
      log_.ped("excluding module (no filter match)", redlog::field("name", name));
    }
    return matches;
  }

  // step 7: check system module policy
  if (module.is_system_library && !config_.include_system_modules) {
    log_.dbg("excluding system module", redlog::field("name", name));
    return false;
  }

  // default: instrument
  log_.dbg("including user module", redlog::field("name", name));
  return true;
}

bool instrumentation_manager::configure_instrumentation(QBDI::VM* vm, const std::vector<util::module_info>& modules) {
  log_.trc("applying instrumentation decisions");

  // log configuration summary at debug level
  if (!config_.module_filter.empty()) {
    log_.dbg("using module filter", redlog::field("patterns", config_.module_filter));
  }
  log_.dbg(
      "instrumentation policy", redlog::field("include_system", config_.include_system_modules),
      redlog::field("use_conflicts", config_.use_default_conflicts),
      redlog::field("use_criticals", config_.use_default_criticals)
  );

  size_t added_count = 0;
  size_t skipped_count = 0;

  for (const auto& module : modules) {
    if (should_instrument_module(module)) {
      // add this module to instrumentation
      log_.ped(
          "adding module to vm instrumentation", redlog::field("name", module.name),
          redlog::field("base", "0x%lx", module.base_address)
      );

      if (vm->addInstrumentedModuleFromAddr(module.base_address)) {
        added_count++;
      } else {
        log_.wrn(
            "failed to add module to instrumentation", redlog::field("name", module.name),
            redlog::field("base", "0x%lx", module.base_address)
        );
      }
    } else {
      skipped_count++;
    }
  }

  log_.inf("instrumentation configured", redlog::field("added", added_count), redlog::field("skipped", skipped_count));

  if (added_count == 0) {
    log_.wrn("no modules were instrumented - check your configuration");
  }

  return added_count > 0;
}

} // namespace w1