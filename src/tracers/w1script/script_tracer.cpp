#include "script_tracer.hpp"
#include <redlog/redlog.hpp>

#ifdef WITNESS_SCRIPT_ENABLED
#include "script_bindings.hpp"
#include <fstream>
#include <stdexcept>
#endif

namespace w1::tracers::script {

bool script_tracer::initialize(w1::tracer_engine<script_tracer>& engine) {
  cfg_ = config::from_environment();

#ifdef WITNESS_SCRIPT_ENABLED
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

  // Enable memory recording if memory callbacks are used
  if (is_callback_enabled("memory_read") || is_callback_enabled("memory_write")) {
    QBDI::VM* vm = engine.get_vm();
    if (vm) {
      bool memory_recording_enabled = vm->recordMemoryAccess(QBDI::MEMORY_READ_WRITE);
      if (memory_recording_enabled) {
        log.inf("memory recording enabled for script");
      } else {
        log.wrn("memory recording not supported on this platform");
      }
    }
  }

  log.inf("initialization complete", redlog::field("enabled_callbacks", enabled_callbacks_.size()));
  return true;
#else
  auto log = redlog::get_logger("w1script.tracer");
  log.wrn("lua support not compiled in. set WITNESS_SCRIPT=ON to enable.");
  return false;
#endif
}

void script_tracer::shutdown() {
#ifdef WITNESS_SCRIPT_ENABLED
  auto log = redlog::get_logger("w1script.tracer");
  if (cfg_.verbose) {
    log.inf("shutting down");
  }

  // Call script shutdown function if it exists
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
#endif
}

#ifdef WITNESS_SCRIPT_ENABLED
bool script_tracer::load_script() {
  try {
    // Initialize Lua state
    lua_.open_libraries(sol::lib::base, sol::lib::table, sol::lib::string, sol::lib::math, sol::lib::io);

    // Setup QBDI bindings
    setup_qbdi_bindings(lua_);

    // Expose config to the script
    sol::table config_table = lua_.create_table();
    for (const auto& pair : cfg_.script_config) {
      config_table[pair.first] = pair.second;
    }
    lua_["config"] = config_table;

    // Load the script
    sol::load_result script = lua_.load_file(cfg_.script_path);
    if (!script.valid()) {
      sol::error err = script;
      auto log = redlog::get_logger("w1script.tracer");
      log.err("failed to load script", redlog::field("error", err.what()));
      return false;
    }

    // Execute the script - it should return a table
    sol::protected_function_result result = script();
    if (!result.valid()) {
      sol::error err = result;
      auto log = redlog::get_logger("w1script.tracer");
      log.err("failed to execute script", redlog::field("error", err.what()));
      return false;
    }

    // Get the returned table
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

  // Get the callbacks list from the script
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

  // Get the callback functions
  lua_on_instruction_preinst_ = script_table_["on_instruction_preinst"];
  lua_on_instruction_postinst_ = script_table_["on_instruction_postinst"];
  lua_on_basic_block_entry_ = script_table_["on_basic_block_entry"];
  lua_on_basic_block_exit_ = script_table_["on_basic_block_exit"];
  lua_on_memory_read_ = script_table_["on_memory_read"];
  lua_on_memory_write_ = script_table_["on_memory_write"];
}

bool script_tracer::is_callback_enabled(const std::string& callback_name) const {
  return enabled_callbacks_.find(callback_name) != enabled_callbacks_.end();
}

QBDI::VMAction script_tracer::on_instruction_preinst(QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr) {
  if (!is_callback_enabled("instruction_preinst")) {
    return QBDI::VMAction::CONTINUE;
  }

  if (lua_on_instruction_preinst_.valid()) {
    try {
      // Pass simplified parameters to avoid type issues
      auto result =
          lua_on_instruction_preinst_(static_cast<void*>(vm), static_cast<void*>(gpr), static_cast<void*>(fpr));
      if (result.valid() && result.get_type() == sol::type::number) {
        return static_cast<QBDI::VMAction>(result.get<int>());
      }
    } catch (const sol::error& e) {
      auto log = redlog::get_logger("w1script.tracer");
      log.err("error in on_instruction_preinst", redlog::field("error", e.what()));
    }
  }
  return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction script_tracer::on_instruction_postinst(
    QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  if (!is_callback_enabled("instruction_postinst")) {
    return QBDI::VMAction::CONTINUE;
  }

  if (lua_on_instruction_postinst_.valid()) {
    try {
      auto result =
          lua_on_instruction_postinst_(static_cast<void*>(vm), static_cast<void*>(gpr), static_cast<void*>(fpr));
      if (result.valid() && result.get_type() == sol::type::number) {
        return static_cast<QBDI::VMAction>(result.get<int>());
      }
    } catch (const sol::error& e) {
      auto log = redlog::get_logger("w1script.tracer");
      log.err("error in on_instruction_postinst", redlog::field("error", e.what()));
    }
  }
  return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction script_tracer::on_basic_block_entry(
    QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  if (!is_callback_enabled("basic_block_entry")) {
    return QBDI::VMAction::CONTINUE;
  }

  if (lua_on_basic_block_entry_.valid()) {
    try {
      auto result = lua_on_basic_block_entry_(
          static_cast<void*>(vm), static_cast<const void*>(state), static_cast<void*>(gpr), static_cast<void*>(fpr)
      );
      if (result.valid() && result.get_type() == sol::type::number) {
        return static_cast<QBDI::VMAction>(result.get<int>());
      }
    } catch (const sol::error& e) {
      auto log = redlog::get_logger("w1script.tracer");
      log.err("error in on_basic_block_entry", redlog::field("error", e.what()));
    }
  }
  return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction script_tracer::on_basic_block_exit(
    QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  if (!is_callback_enabled("basic_block_exit")) {
    return QBDI::VMAction::CONTINUE;
  }

  if (lua_on_basic_block_exit_.valid()) {
    try {
      auto result = lua_on_basic_block_exit_(
          static_cast<void*>(vm), static_cast<const void*>(state), static_cast<void*>(gpr), static_cast<void*>(fpr)
      );
      if (result.valid() && result.get_type() == sol::type::number) {
        return static_cast<QBDI::VMAction>(result.get<int>());
      }
    } catch (const sol::error& e) {
      auto log = redlog::get_logger("w1script.tracer");
      log.err("error in on_basic_block_exit", redlog::field("error", e.what()));
    }
  }
  return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction script_tracer::on_memory_read(QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr) {
  if (!is_callback_enabled("memory_read")) {
    return QBDI::VMAction::CONTINUE;
  }

  if (lua_on_memory_read_.valid()) {
    try {
      auto result = lua_on_memory_read_(static_cast<void*>(vm), static_cast<void*>(gpr), static_cast<void*>(fpr));
      if (result.valid() && result.get_type() == sol::type::number) {
        return static_cast<QBDI::VMAction>(result.get<int>());
      }
    } catch (const sol::error& e) {
      auto log = redlog::get_logger("w1script.tracer");
      log.err("error in on_memory_read", redlog::field("error", e.what()));
    }
  }
  return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction script_tracer::on_memory_write(QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr) {
  if (!is_callback_enabled("memory_write")) {
    return QBDI::VMAction::CONTINUE;
  }

  if (lua_on_memory_write_.valid()) {
    try {
      auto result = lua_on_memory_write_(static_cast<void*>(vm), static_cast<void*>(gpr), static_cast<void*>(fpr));
      if (result.valid() && result.get_type() == sol::type::number) {
        return static_cast<QBDI::VMAction>(result.get<int>());
      }
    } catch (const sol::error& e) {
      auto log = redlog::get_logger("w1script.tracer");
      log.err("error in on_memory_write", redlog::field("error", e.what()));
    }
  }
  return QBDI::VMAction::CONTINUE;
}
#endif

} // namespace w1::tracers::script