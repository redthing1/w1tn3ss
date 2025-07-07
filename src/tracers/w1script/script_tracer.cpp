#include "script_tracer.hpp"
#include <redlog.hpp>

#include "script_bindings.hpp"
#include "bindings/api_analysis.hpp"
#include <w1tn3ss/util/module_scanner.hpp>
#include <w1tn3ss/util/module_range_index.hpp>
#include <w1tn3ss/util/register_access.hpp>
#include <w1tn3ss/lief/symbol_resolver.hpp>
#include <fstream>
#include <stdexcept>
#include <chrono>

namespace w1::tracers::script {

script_tracer::script_tracer() : logger_(redlog::get_logger("w1.script_tracer")) {}
script_tracer::~script_tracer() = default;

bool script_tracer::initialize(w1::tracer_engine<script_tracer>& engine) {
  cfg_ = config::from_environment();

  if (!cfg_.is_valid()) {
    logger_.err("invalid configuration. W1SCRIPT_SCRIPT must be specified.");
    return false;
  }
  logger_.inf("initializing with lua support");
  logger_.inf("script path", redlog::field("path", cfg_.script_path));

  if (!load_script()) {
    logger_.err("failed to load script");
    return false;
  }

  setup_callbacks();

  // register callbacks dynamically based on script requirements
  QBDI::VM* vm = engine.get_vm();
  if (vm) {
    register_callbacks_dynamically(vm);

    // enable memory recording if memory callbacks are used
    if (is_callback_enabled("memory_read") || is_callback_enabled("memory_write") ||
        is_callback_enabled("memory_read_write")) {
      bool memory_recording_enabled = vm->recordMemoryAccess(QBDI::MEMORY_READ_WRITE);
      if (memory_recording_enabled) {
        logger_.inf("memory recording enabled for script");
      } else {
        logger_.wrn("memory recording not supported on this platform");
      }
    }
  } else {
    logger_.err("vm instance is null, cannot register callbacks");
    return false;
  }

  // scan modules and create index
  w1::util::module_scanner scanner;
  auto modules = scanner.scan_executable_modules();
  module_index_ = std::make_unique<w1::util::module_range_index>();
  module_index_->rebuild_from_modules(std::move(modules));
  logger_.inf("module index built", redlog::field("module_count", module_index_->size()));

  // create symbol resolver if lief is enabled
#ifdef WITNESS_LIEF_ENABLED
  symbol_resolver_ = std::make_unique<w1::lief::symbol_resolver>();
  logger_.inf("symbol resolver created");
#endif

  // initialize api manager if created
  if (api_manager_) {
    logger_.inf("initializing api manager");
    api_manager_->initialize(*module_index_);
  }

  logger_.inf("initialization complete", redlog::field("enabled_callbacks", enabled_callbacks_.size()));
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

  // clear registered callbacks
  registered_callback_ids_.clear();
  lua_callbacks_.clear();

  // shutdown api manager if it exists
  if (api_manager_) {
    api_manager_->shutdown();
  }
}

bool script_tracer::load_script() {
  try {
    // initialize lua state
    lua_.open_libraries(sol::lib::base, sol::lib::table, sol::lib::string, sol::lib::math, sol::lib::io);

    // we'll set up bindings after we have the script table

    // expose config to the script
    sol::table config_table = lua_.create_table();
    for (const auto& pair : cfg_.script_config) {
      config_table[pair.first] = pair.second;
    }
    lua_["config"] = config_table;

    // load the script
    sol::load_result script = lua_.load_file(cfg_.script_path);
    if (!script.valid()) {
      sol::error err = script;
      logger_.err("failed to load script", redlog::field("error", err.what()));
      return false;
    }

    // execute the script - it should return a table
    sol::protected_function_result result = script();
    if (!result.valid()) {
      sol::error err = result;
      logger_.err("failed to execute script", redlog::field("error", err.what()));
      return false;
    }

    // get the returned table
    if (!result.return_count() || result.get_type() != sol::type::table) {
      logger_.err("script must return a table");
      return false;
    }

    script_table_ = result;

    // now setup qbdi bindings with the script table
    setup_qbdi_bindings(lua_, script_table_, api_manager_);

    // call init function if it exists
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

    return true;
  } catch (const std::exception& e) {
    logger_.err("exception loading script", redlog::field("error", e.what()));
    return false;
  }
}

void script_tracer::setup_callbacks() {
  if (!script_table_.valid()) {
    return;
  }

  // get the callbacks list from the script
  sol::optional<sol::table> callbacks_table = script_table_["callbacks"];
  if (callbacks_table) {
    for (const auto& pair : callbacks_table.value()) {
      if (pair.second.get_type() == sol::type::string) {
        std::string callback_name = pair.second.as<std::string>();
        enabled_callbacks_.insert(callback_name);
        logger_.dbg("found callback", redlog::field("name", callback_name));
      }
    }
  }

  // get all possible callback functions from the script
  const std::vector<std::string> all_callbacks = {
      "on_instruction_preinst",
      "on_instruction_postinst",
      "on_sequence_entry",
      "on_sequence_exit",
      "on_basic_block_entry",
      "on_basic_block_exit",
      "on_basic_block_new",
      "on_exec_transfer_call",
      "on_exec_transfer_return",
      "on_memory_read",
      "on_memory_write",
      "on_memory_read_write",
      "on_code_addr",
      "on_code_range",
      "on_mnemonic",
      "on_mem_addr",
      "on_mem_range",
      "on_instr_rule",
      "on_instr_rule_range",
      "on_instr_rule_range_set"
  };

  for (const auto& callback_name : all_callbacks) {
    sol::function callback_fn = script_table_[callback_name];
    if (callback_fn.valid()) {
      lua_callbacks_[callback_name] = callback_fn;
    }
  }
}

bool script_tracer::is_callback_enabled(const std::string& callback_name) const {
  return enabled_callbacks_.find(callback_name) != enabled_callbacks_.end();
}

void script_tracer::register_callbacks_dynamically(QBDI::VM* vm) {
  logger_.inf("registering callbacks dynamically based on script requirements");

  // instruction callbacks (addCodeCB)
  if (is_callback_enabled("instruction_preinst")) {
    uint32_t id = vm->addCodeCB(
        QBDI::PREINST, [this](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr) -> QBDI::VMAction {
          return this->dispatch_simple_callback("on_instruction_preinst", vm, gpr, fpr);
        }
    );
    if (id != QBDI::INVALID_EVENTID) {
      registered_callback_ids_.push_back(id);
      logger_.inf("registered instruction_preinst callback", redlog::field("id", id));
    }
  }

  if (is_callback_enabled("instruction_postinst")) {
    uint32_t id = vm->addCodeCB(
        QBDI::POSTINST, [this](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr) -> QBDI::VMAction {
          return this->dispatch_simple_callback("on_instruction_postinst", vm, gpr, fpr);
        }
    );
    if (id != QBDI::INVALID_EVENTID) {
      registered_callback_ids_.push_back(id);
      logger_.inf("registered instruction_postinst callback", redlog::field("id", id));
    }
  }

  // vm event callbacks (addVMEventCB)
  const std::vector<std::pair<std::string, QBDI::VMEvent>> vm_events = {
      {"sequence_entry", QBDI::SEQUENCE_ENTRY},
      {"sequence_exit", QBDI::SEQUENCE_EXIT},
      {"basic_block_entry", QBDI::BASIC_BLOCK_ENTRY},
      {"basic_block_exit", QBDI::BASIC_BLOCK_EXIT},
      {"basic_block_new", QBDI::BASIC_BLOCK_NEW},
      {"exec_transfer_call", QBDI::EXEC_TRANSFER_CALL},
      {"exec_transfer_return", QBDI::EXEC_TRANSFER_RETURN}
  };

  for (const auto& [callback_name, event] : vm_events) {
    if (is_callback_enabled(callback_name)) {
      std::string lua_callback_name = "on_" + callback_name;
      uint32_t id = vm->addVMEventCB(
          event,
          [this, lua_callback_name](
              QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr
          ) -> QBDI::VMAction { return this->dispatch_vm_event_callback(lua_callback_name, vm, state, gpr, fpr); }
      );
      if (id != QBDI::INVALID_EVENTID) {
        registered_callback_ids_.push_back(id);
        logger_.inf("registered vm event callback", redlog::field("name", callback_name), redlog::field("id", id));
      }
    }
  }

  // memory access callbacks (addMemAccessCB)
  const std::vector<std::pair<std::string, QBDI::MemoryAccessType>> memory_accesses = {
      {"memory_read", QBDI::MEMORY_READ},
      {"memory_write", QBDI::MEMORY_WRITE},
      {"memory_read_write", QBDI::MEMORY_READ_WRITE}
  };

  for (const auto& [callback_name, access_type] : memory_accesses) {
    if (is_callback_enabled(callback_name)) {
      std::string lua_callback_name = "on_" + callback_name;
      uint32_t id = vm->addMemAccessCB(
          access_type,
          [this, lua_callback_name](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr)
              -> QBDI::VMAction { return this->dispatch_simple_callback(lua_callback_name, vm, gpr, fpr); }
      );
      if (id != QBDI::INVALID_EVENTID) {
        registered_callback_ids_.push_back(id);
        logger_.inf("registered memory access callback", redlog::field("name", callback_name), redlog::field("id", id));
      }
    }
  }

  logger_.inf(
      "dynamic callback registration complete", redlog::field("total_callbacks", registered_callback_ids_.size())
  );
}

QBDI::VMAction script_tracer::dispatch_simple_callback(
    const std::string& callback_name, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  auto it = lua_callbacks_.find(callback_name);
  if (it == lua_callbacks_.end() || !it->second.valid()) {
    return QBDI::VMAction::CONTINUE;
  }

  try {
    auto result = it->second(static_cast<void*>(vm), static_cast<void*>(gpr), static_cast<void*>(fpr));
    if (result.valid() && result.get_type() == sol::type::number) {
      return static_cast<QBDI::VMAction>(result.get<int>());
    }
  } catch (const sol::error& e) {
    logger_.err("error in callback", redlog::field("callback", callback_name), redlog::field("error", e.what()));
  }
  return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction script_tracer::dispatch_vm_event_callback(
    const std::string& callback_name, QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  // process api analysis for exec_transfer events
  if (api_manager_ && module_index_ &&
      (callback_name == "on_exec_transfer_call" || callback_name == "on_exec_transfer_return")) {
    // build api context
    w1::abi::api_context ctx;
    ctx.vm = vm;
    ctx.vm_state = state;
    ctx.gpr_state = gpr;
    ctx.fpr_state = fpr;
    ctx.module_index = module_index_.get();
    ctx.timestamp = std::chrono::steady_clock::now().time_since_epoch().count();

    if (callback_name == "on_exec_transfer_call") {
      // for calls: source is where we're calling from, target is what we're calling
      ctx.call_address = state->sequenceStart;
      ctx.target_address = w1::registers::get_pc(gpr);

      // get module and symbol names
      if (auto module_info = module_index_->find_containing(ctx.target_address)) {
        ctx.module_name = module_info->name;

        // resolve symbol if we have a resolver
#ifdef WITNESS_LIEF_ENABLED
        if (symbol_resolver_) {
          if (auto sym_info = symbol_resolver_->resolve(ctx.target_address, *module_index_)) {
            ctx.symbol_name = sym_info->name;
          }
        }
#endif
      }

      logger_.dbg(
          "processing api call", redlog::field("target", ctx.target_address), redlog::field("module", ctx.module_name),
          redlog::field("symbol", ctx.symbol_name)
      );
      api_manager_->process_call(ctx);
    } else {
      // for returns: source is what we're returning from, target is where we're returning to
      ctx.target_address = state->sequenceStart;
      ctx.call_address = w1::registers::get_pc(gpr);

      // get module and symbol names
      if (auto module_info = module_index_->find_containing(ctx.target_address)) {
        ctx.module_name = module_info->name;

        // resolve symbol if we have a resolver
#ifdef WITNESS_LIEF_ENABLED
        if (symbol_resolver_) {
          if (auto sym_info = symbol_resolver_->resolve(ctx.target_address, *module_index_)) {
            ctx.symbol_name = sym_info->name;
          }
        }
#endif
      }

      api_manager_->process_return(ctx);
    }
  }

  auto it = lua_callbacks_.find(callback_name);
  if (it == lua_callbacks_.end() || !it->second.valid()) {
    return QBDI::VMAction::CONTINUE;
  }

  try {
    auto result = it->second(static_cast<void*>(vm), *state, static_cast<void*>(gpr), static_cast<void*>(fpr));
    if (result.valid() && result.get_type() == sol::type::number) {
      return static_cast<QBDI::VMAction>(result.get<int>());
    }
  } catch (const sol::error& e) {
    logger_.err(
        "error in vm event callback", redlog::field("callback", callback_name), redlog::field("error", e.what())
    );
  }
  return QBDI::VMAction::CONTINUE;
}

std::vector<QBDI::InstrRuleDataCBK> script_tracer::dispatch_instr_rule_callback(
    const std::string& callback_name, QBDI::VMInstanceRef vm, const QBDI::InstAnalysis* analysis, void* data
) {
  auto it = lua_callbacks_.find(callback_name);
  if (it == lua_callbacks_.end() || !it->second.valid()) {
    return {};
  }

  try {
    auto result = it->second(static_cast<void*>(vm), static_cast<const void*>(analysis), data);
    // for now, return empty vector - instruction rules require more complex handling
    return {};
  } catch (const sol::error& e) {
    logger_.err(
        "error in instr rule callback", redlog::field("callback", callback_name), redlog::field("error", e.what())
    );
  }
  return {};
}

} // namespace w1::tracers::script