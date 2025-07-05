#include "script_tracer.hpp"
#include <redlog.hpp>

#include "script_bindings.hpp"
#include <fstream>
#include <stdexcept>

namespace w1::tracers::script {

bool script_tracer::initialize(w1::tracer_engine<script_tracer>& engine) {
  cfg_ = config::from_environment();

  if (!cfg_.is_valid()) {
    auto log = redlog::get_logger("w1script.tracer");
    log.err("invalid configuration. W1SCRIPT_SCRIPT must be specified.");
    return false;
  }

  auto log = redlog::get_logger("w1script.tracer");
  log.inf("initializing with Lua support");
  log.inf("script path", redlog::field("path", cfg_.script_path));

  if (!load_script()) {
    log.err("failed to load script");
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
        log.inf("memory recording enabled for script");
      } else {
        log.wrn("memory recording not supported on this platform");
      }
    }
  } else {
    log.err("VM instance is null, cannot register callbacks");
    return false;
  }

  log.inf("initialization complete", redlog::field("enabled_callbacks", enabled_callbacks_.size()));
  return true;
}

void script_tracer::shutdown() {
  auto log = redlog::get_logger("w1script.tracer");
  if (cfg_.verbose) {
    log.inf("shutting down");
  }

  // call script shutdown function if it exists
  if (script_table_.valid()) {
    sol::optional<sol::function> shutdown_fn = script_table_["shutdown"];
    if (shutdown_fn) {
      try {
        shutdown_fn.value()();
      } catch (const sol::error& e) {
        log.err("error in script shutdown", redlog::field("error", e.what()));
      }
    }
  }

  // clear registered callbacks
  registered_callback_ids_.clear();
  lua_callbacks_.clear();
}

bool script_tracer::load_script() {
  try {
    // initialize Lua state
    lua_.open_libraries(sol::lib::base, sol::lib::table, sol::lib::string, sol::lib::math, sol::lib::io);

    // setup QBDI bindings
    setup_qbdi_bindings(lua_);

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
      auto log = redlog::get_logger("w1script.tracer");
      log.err("failed to load script", redlog::field("error", err.what()));
      return false;
    }

    // execute the script - it should return a table
    sol::protected_function_result result = script();
    if (!result.valid()) {
      sol::error err = result;
      auto log = redlog::get_logger("w1script.tracer");
      log.err("failed to execute script", redlog::field("error", err.what()));
      return false;
    }

    // get the returned table
    if (!result.return_count() || result.get_type() != sol::type::table) {
      auto log = redlog::get_logger("w1script.tracer");
      log.err("script must return a table");
      return false;
    }

    script_table_ = result;

    return true;
  } catch (const std::exception& e) {
    auto log = redlog::get_logger("w1script.tracer");
    log.err("exception loading script", redlog::field("error", e.what()));
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
        auto log = redlog::get_logger("w1script.tracer");
        log.dbg("found callback", redlog::field("name", callback_name));
      }
    }
  }

  // get ALL possible callback functions from the script
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
  auto log = redlog::get_logger("w1script.tracer");
  log.inf("registering callbacks dynamically based on script requirements");

  // instruction callbacks (addCodeCB)
  if (is_callback_enabled("instruction_preinst")) {
    uint32_t id = vm->addCodeCB(
        QBDI::PREINST, [this](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr) -> QBDI::VMAction {
          return this->dispatch_simple_callback("on_instruction_preinst", vm, gpr, fpr);
        }
    );
    if (id != QBDI::INVALID_EVENTID) {
      registered_callback_ids_.push_back(id);
      log.inf("registered instruction_preinst callback", redlog::field("id", id));
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
      log.inf("registered instruction_postinst callback", redlog::field("id", id));
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
        log.inf("registered vm event callback", redlog::field("name", callback_name), redlog::field("id", id));
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
        log.inf("registered memory access callback", redlog::field("name", callback_name), redlog::field("id", id));
      }
    }
  }

  log.inf("dynamic callback registration complete", redlog::field("total_callbacks", registered_callback_ids_.size()));
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
    auto log = redlog::get_logger("w1script.tracer");
    log.err("error in callback", redlog::field("callback", callback_name), redlog::field("error", e.what()));
  }
  return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction script_tracer::dispatch_vm_event_callback(
    const std::string& callback_name, QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
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
    auto log = redlog::get_logger("w1script.tracer");
    log.err("error in vm event callback", redlog::field("callback", callback_name), redlog::field("error", e.what()));
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
    auto log = redlog::get_logger("w1script.tracer");
    log.err("error in instr rule callback", redlog::field("callback", callback_name), redlog::field("error", e.what()));
  }
  return {};
}

} // namespace w1::tracers::script