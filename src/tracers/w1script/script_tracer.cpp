#include "script_tracer.hpp"
#include <redlog.hpp>

#include "script_bindings.hpp"
#include "script_loader.hpp"
#include "callback_manager.hpp"
#include "bindings/api_analysis.hpp"
#include <w1tn3ss/util/module_scanner.hpp>
#include <w1tn3ss/util/module_range_index.hpp>
#include <w1tn3ss/util/register_access.hpp>
#include <w1tn3ss/symbols/symbol_resolver.hpp>
#include <w1tn3ss/hooking/hook_manager.hpp>
#include <w1tn3ss/gadget/gadget_executor.hpp>
#include <fstream>
#include <stdexcept>

namespace w1::tracers::script {

script_tracer::script_tracer() : logger_(redlog::get_logger("w1.script_tracer")) {}

script_tracer::script_tracer(const config& cfg) : cfg_(cfg), logger_(redlog::get_logger("w1.script_tracer")) {}

script_tracer::~script_tracer() = default;

bool script_tracer::initialize(w1::tracer_engine<script_tracer>& engine) {
  // if cfg_ not already set, get from environment
  if (cfg_.script_path.empty()) {
    cfg_ = config::from_environment();
  }

  if (!cfg_.is_valid()) {
    logger_.err("invalid configuration. W1SCRIPT_SCRIPT must be specified.");
    return false;
  }
  logger_.inf("initializing with lua support");
  logger_.inf("script path", redlog::field("path", cfg_.script_path));

  // get VM and create hook manager early
  QBDI::VM* vm = engine.get_vm();
  if (!vm) {
    logger_.err("vm instance is null");
    return false;
  }

  // create hook manager before loading script
  hook_manager_ = std::make_shared<w1::hooking::hook_manager>(vm);
  logger_.inf("hook manager created");

  // create gadget executor before loading script
  gadget_executor_ = std::make_shared<w1tn3ss::gadget::gadget_executor>(vm);
  logger_.inf("gadget executor initialized");

  // create api analysis processor
  api_processor_ = std::make_unique<api_analysis_processor>();

  // create api analysis manager
  api_manager_ = std::make_shared<bindings::api_analysis_manager>();

  // initialize lua state
  lua_.open_libraries(sol::lib::base, sol::lib::table, sol::lib::string, sol::lib::math, sol::lib::io);

  // setup bindings before loading script (without API analysis yet)
  sol::table dummy_table = lua_.create_table();
  setup_qbdi_bindings(lua_, dummy_table, api_manager_, hook_manager_, gadget_executor_);

  // load script using the new loader
  script_loader loader;
  auto load_result = loader.load_script(lua_, cfg_);
  if (!load_result.success) {
    logger_.err("failed to load script", redlog::field("error", load_result.error_message));
    return false;
  }
  script_table_ = load_result.script_table;

  // inject API analysis methods into the script table
  logger_.inf("setting up api analysis methods on script table");
  if (api_manager_) {
    sol::table w1_module = lua_["w1"];
    bindings::setup_api_analysis(lua_, w1_module, script_table_, api_manager_);
    logger_.inf("api analysis methods setup complete");
  } else {
    logger_.wrn("api_manager_ is null, skipping api analysis setup");
  }

  // now call the script's init function
  sol::optional<sol::function> init_fn = script_table_["init"];
  if (init_fn) {
    try {
      logger_.dbg("calling script init function");
      init_fn.value()();
    } catch (const sol::error& e) {
      logger_.err("error in script init function", redlog::field("error", e.what()));
      return false;
    }
  }

  // scan modules and create index first
  w1::util::module_scanner scanner;
  auto modules = scanner.scan_executable_modules();
  module_index_ = std::make_unique<w1::util::module_range_index>();
  module_index_->rebuild_from_modules(std::move(modules));
  logger_.inf("module index built", redlog::field("module_count", module_index_->size()));

  // create symbol resolver
  symbol_resolver_ = std::make_unique<w1::symbols::symbol_resolver>();
  logger_.inf("symbol resolver created");

  // initialize api manager if created
  if (api_manager_) {
    logger_.inf("initializing api manager");
    api_manager_->initialize(*module_index_);
  }

  // check if script has an instrument function for manual callback registration
  sol::optional<sol::function> instrument_fn = script_table_["instrument"];
  if (instrument_fn) {
    try {
      logger_.inf("calling script instrument function for manual callback registration");
      instrument_fn.value()(vm);
    } catch (const sol::error& e) {
      logger_.err("error in script instrument function", redlog::field("error", e.what()));
      return false;
    }
  } else {
    // fallback to automatic callback registration based on tracer.callbacks
    // setup callbacks using the new manager
    callback_manager_ = std::make_unique<callback_manager>();
    callback_manager_->setup_callbacks(script_table_);

    // pass api analysis components to callback manager
    callback_manager_->set_api_analysis_components(
        api_processor_.get(), api_manager_.get(), module_index_.get(), symbol_resolver_.get()
    );

    callback_manager_->register_callbacks(vm);
  }

  // enable memory recording if memory callbacks are used (only applies to automatic registration)
  if (callback_manager_ &&
      (callback_manager_->is_callback_enabled(callback_manager::callback_type::memory_read) ||
       callback_manager_->is_callback_enabled(callback_manager::callback_type::memory_write) ||
       callback_manager_->is_callback_enabled(callback_manager::callback_type::memory_read_write))) {
    bool memory_recording_enabled = vm->recordMemoryAccess(QBDI::MEMORY_READ_WRITE);
    if (memory_recording_enabled) {
      logger_.inf("memory recording enabled for script");
    } else {
      logger_.wrn("memory recording not supported on this platform");
    }
  }

  logger_.inf("initialization complete");
  return true;
}

void script_tracer::shutdown() {
  if (cfg_.verbose) {
    logger_.inf("shutting down");
  }

  // call script shutdown function if it exists
  if (script_table_.valid()) {
    sol::optional<sol::function> shutdown_fn = script_table_["shutdown"];
    if (shutdown_fn) {
      try {
        shutdown_fn.value()();
      } catch (const sol::error& e) {
        logger_.err("error in script shutdown", redlog::field("error", e.what()));
      }
    }
  }

  // close output module if it's initialized
  if (lua_["w1"]["output"].valid() && lua_["w1"]["output"]["close"].valid()) {
    try {
      lua_["w1"]["output"]["close"]();
    } catch (const sol::error& e) {
      logger_.err("error closing output module", redlog::field("error", e.what()));
    }
  }

  // shutdown api manager if it exists
  if (api_manager_) {
    api_manager_->shutdown();
  }

  // clear all VM callbacks to prevent use-after-free
  // call the cleanup function if it exists in w1 module
  if (lua_["w1"].valid() && lua_["w1"]["_cleanup_vm_callbacks"].valid()) {
    try {
      lua_["w1"]["_cleanup_vm_callbacks"]();
    } catch (...) {
      // ignore errors during cleanup
    }
  }
}

// all callbacks are registered manually by callback_manager
// we don't define any on_* methods to prevent tracer_engine from registering callbacks

QBDI::VMAction script_tracer::on_vm_start(QBDI::VMInstanceRef vm) {
  logger_.dbg("on_vm_start called");

  // check if the script has an on_vm_start callback
  if (!callback_manager_->is_callback_enabled(callback_manager::callback_type::vm_start)) {
    logger_.dbg("no on_vm_start callback in script, continuing");
    return QBDI::VMAction::CONTINUE;
  }

  // dispatch to the lua callback - just vm
  QBDI::VMAction action = callback_manager_->dispatch_vm_start_callback(vm);

  logger_.dbg("on_vm_start callback returned", redlog::field("action", static_cast<int>(action)));

  return action;
}

} // namespace w1::tracers::script