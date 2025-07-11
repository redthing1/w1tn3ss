#include "callback_manager.hpp"
#include "api_analysis_processor.hpp"
#include "bindings/api_analysis.hpp"
#include <w1tn3ss/util/module_range_index.hpp>
#include <w1tn3ss/symbols/symbol_resolver.hpp>
#include <algorithm>

namespace w1::tracers::script {

namespace {
// mapping of string names to callback types
const std::unordered_map<std::string, callback_manager::callback_type> callback_name_map = {
    {"instruction_preinst", callback_manager::callback_type::instruction_preinst},
    {"instruction_postinst", callback_manager::callback_type::instruction_postinst},
    {"sequence_entry", callback_manager::callback_type::sequence_entry},
    {"sequence_exit", callback_manager::callback_type::sequence_exit},
    {"basic_block_entry", callback_manager::callback_type::basic_block_entry},
    {"basic_block_exit", callback_manager::callback_type::basic_block_exit},
    {"basic_block_new", callback_manager::callback_type::basic_block_new},
    {"exec_transfer_call", callback_manager::callback_type::exec_transfer_call},
    {"exec_transfer_return", callback_manager::callback_type::exec_transfer_return},
    {"memory_read", callback_manager::callback_type::memory_read},
    {"memory_write", callback_manager::callback_type::memory_write},
    {"memory_read_write", callback_manager::callback_type::memory_read_write},
    {"code_addr", callback_manager::callback_type::code_addr},
    {"code_range", callback_manager::callback_type::code_range},
    {"mnemonic", callback_manager::callback_type::mnemonic},
    {"mem_addr", callback_manager::callback_type::mem_addr},
    {"mem_range", callback_manager::callback_type::mem_range},
    {"instr_rule", callback_manager::callback_type::instr_rule},
    {"instr_rule_range", callback_manager::callback_type::instr_rule_range},
    {"instr_rule_range_set", callback_manager::callback_type::instr_rule_range_set}
};

// mapping of callback types to lua function names
const std::unordered_map<callback_manager::callback_type, std::string> lua_function_names = {
    {callback_manager::callback_type::instruction_preinst, "on_instruction_preinst"},
    {callback_manager::callback_type::instruction_postinst, "on_instruction_postinst"},
    {callback_manager::callback_type::sequence_entry, "on_sequence_entry"},
    {callback_manager::callback_type::sequence_exit, "on_sequence_exit"},
    {callback_manager::callback_type::basic_block_entry, "on_basic_block_entry"},
    {callback_manager::callback_type::basic_block_exit, "on_basic_block_exit"},
    {callback_manager::callback_type::basic_block_new, "on_basic_block_new"},
    {callback_manager::callback_type::exec_transfer_call, "on_exec_transfer_call"},
    {callback_manager::callback_type::exec_transfer_return, "on_exec_transfer_return"},
    {callback_manager::callback_type::memory_read, "on_memory_read"},
    {callback_manager::callback_type::memory_write, "on_memory_write"},
    {callback_manager::callback_type::memory_read_write, "on_memory_read_write"},
    {callback_manager::callback_type::code_addr, "on_code_addr"},
    {callback_manager::callback_type::code_range, "on_code_range"},
    {callback_manager::callback_type::mnemonic, "on_mnemonic"},
    {callback_manager::callback_type::mem_addr, "on_mem_addr"},
    {callback_manager::callback_type::mem_range, "on_mem_range"},
    {callback_manager::callback_type::instr_rule, "on_instr_rule"},
    {callback_manager::callback_type::instr_rule_range, "on_instr_rule_range"},
    {callback_manager::callback_type::instr_rule_range_set, "on_instr_rule_range_set"}
};
} // namespace

callback_manager::callback_manager() : logger_(redlog::get_logger("w1.callback_manager")) {}

std::optional<callback_manager::callback_type> callback_manager::string_to_callback_type(const std::string& name) {
  auto it = callback_name_map.find(name);
  if (it != callback_name_map.end()) {
    return it->second;
  }
  return std::nullopt;
}

std::string callback_manager::get_lua_function_name(callback_type type) {
  auto it = lua_function_names.find(type);
  if (it != lua_function_names.end()) {
    return it->second;
  }
  return "";
}

void callback_manager::setup_callbacks(const sol::table& script_table) {
  if (!script_table.valid()) {
    return;
  }

  // auto-detect callback functions by checking for on_* functions
  for (const auto& [type, lua_name] : lua_function_names) {
    sol::function callback_fn = script_table[lua_name];
    if (callback_fn.valid()) {
      lua_callbacks_[type] = callback_fn;
      enabled_callbacks_.insert(type);
      logger_.dbg("detected callback function", redlog::field("name", lua_name));
    }
  }

  logger_.inf(
      "callbacks setup complete", redlog::field("enabled", enabled_callbacks_.size()),
      redlog::field("functions", lua_callbacks_.size())
  );
}

void callback_manager::register_callbacks(QBDI::VM* vm) {
  logger_.inf("registering callbacks dynamically based on script requirements");

  // instruction callbacks (addCodeCB)
  if (is_callback_enabled(callback_type::instruction_preinst)) {
    logger_.trc("script has instruction_preinst callback, registering with QBDI");
    uint32_t id = vm->addCodeCB(
        QBDI::PREINST, [this](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr) -> QBDI::VMAction {
          return this->dispatch_simple_callback(callback_type::instruction_preinst, vm, gpr, fpr);
        }
    );
    if (id != QBDI::INVALID_EVENTID) {
      registered_callback_ids_.push_back(id);
      logger_.inf("registered instruction_preinst callback", redlog::field("id", id));
    }
  } else {
    logger_.trc("script does not have instruction_preinst callback, skipping");
  }

  if (is_callback_enabled(callback_type::instruction_postinst)) {
    logger_.trc("script has instruction_postinst callback, registering with QBDI");
    uint32_t id = vm->addCodeCB(
        QBDI::POSTINST, [this](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr) -> QBDI::VMAction {
          return this->dispatch_simple_callback(callback_type::instruction_postinst, vm, gpr, fpr);
        }
    );
    if (id != QBDI::INVALID_EVENTID) {
      registered_callback_ids_.push_back(id);
      logger_.inf("registered instruction_postinst callback", redlog::field("id", id));
    }
  } else {
    logger_.trc("script does not have instruction_postinst callback, skipping");
  }

  // vm event callbacks (addVMEventCB)
  const std::vector<std::pair<callback_type, QBDI::VMEvent>> vm_events = {
      {callback_type::sequence_entry, QBDI::SEQUENCE_ENTRY},
      {callback_type::sequence_exit, QBDI::SEQUENCE_EXIT},
      {callback_type::basic_block_entry, QBDI::BASIC_BLOCK_ENTRY},
      {callback_type::basic_block_exit, QBDI::BASIC_BLOCK_EXIT},
      {callback_type::basic_block_new, QBDI::BASIC_BLOCK_NEW},
      {callback_type::exec_transfer_call, QBDI::EXEC_TRANSFER_CALL},
      {callback_type::exec_transfer_return, QBDI::EXEC_TRANSFER_RETURN}
  };

  for (const auto& [cb_type, event] : vm_events) {
    if (is_callback_enabled(cb_type)) {
      uint32_t id = vm->addVMEventCB(
          event,
          [this, cb_type](QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr)
              -> QBDI::VMAction { return this->dispatch_vm_event_callback(cb_type, vm, state, gpr, fpr); }
      );
      if (id != QBDI::INVALID_EVENTID) {
        registered_callback_ids_.push_back(id);
        logger_.inf(
            "registered vm event callback", redlog::field("type", static_cast<int>(cb_type)), redlog::field("id", id)
        );
      }
    }
  }

  // memory access callbacks (addMemAccessCB)
  const std::vector<std::pair<callback_type, QBDI::MemoryAccessType>> memory_accesses = {
      {callback_type::memory_read, QBDI::MEMORY_READ},
      {callback_type::memory_write, QBDI::MEMORY_WRITE},
      {callback_type::memory_read_write, QBDI::MEMORY_READ_WRITE}
  };

  for (const auto& [cb_type, access_type] : memory_accesses) {
    if (is_callback_enabled(cb_type)) {
      uint32_t id = vm->addMemAccessCB(
          access_type,
          [this, cb_type](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr) -> QBDI::VMAction {
            return this->dispatch_simple_callback(cb_type, vm, gpr, fpr);
          }
      );
      if (id != QBDI::INVALID_EVENTID) {
        registered_callback_ids_.push_back(id);
        logger_.inf(
            "registered memory access callback", redlog::field("type", static_cast<int>(cb_type)),
            redlog::field("id", id)
        );
      }
    }
  }

  logger_.inf(
      "dynamic callback registration complete", redlog::field("total_callbacks", registered_callback_ids_.size())
  );

  // Log summary at trace level
  logger_.trc(
      "callback registration summary", redlog::field("enabled_callbacks", enabled_callbacks_.size()),
      redlog::field("lua_functions", lua_callbacks_.size()),
      redlog::field("registered_with_qbdi", registered_callback_ids_.size())
  );
}

QBDI::VMAction callback_manager::dispatch_simple_callback(
    callback_type type, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  auto it = lua_callbacks_.find(type);
  if (it == lua_callbacks_.end() || !it->second.valid()) {
    return QBDI::VMAction::CONTINUE;
  }

  try {
    auto result = it->second(vm, gpr, fpr);
    if (result.valid() && result.get_type() == sol::type::number) {
      return static_cast<QBDI::VMAction>(result.get<int>());
    }
  } catch (const sol::error& e) {
    logger_.err("error in callback", redlog::field("type", static_cast<int>(type)), redlog::field("error", e.what()));
  }
  return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction callback_manager::dispatch_vm_event_callback(
    callback_type type, QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  // handle api analysis for exec_transfer events before calling lua
  if (api_processor_ && api_manager_ && module_index_ &&
      (type == callback_type::exec_transfer_call || type == callback_type::exec_transfer_return)) {
    if (type == callback_type::exec_transfer_call) {
      api_processor_->process_call(vm, state, gpr, fpr, api_manager_, module_index_, symbol_resolver_);
    } else {
      api_processor_->process_return(vm, state, gpr, fpr, api_manager_, module_index_, symbol_resolver_);
    }
  }

  auto it = lua_callbacks_.find(type);
  if (it == lua_callbacks_.end() || !it->second.valid()) {
    return QBDI::VMAction::CONTINUE;
  }

  try {
    auto result = it->second(vm, *state, gpr, fpr);
    if (result.valid() && result.get_type() == sol::type::number) {
      return static_cast<QBDI::VMAction>(result.get<int>());
    }
  } catch (const sol::error& e) {
    logger_.err(
        "error in vm event callback", redlog::field("type", static_cast<int>(type)), redlog::field("error", e.what())
    );
  }
  return QBDI::VMAction::CONTINUE;
}

std::vector<QBDI::InstrRuleDataCBK> callback_manager::dispatch_instr_rule_callback(
    callback_type type, QBDI::VMInstanceRef vm, const QBDI::InstAnalysis* analysis, void* data
) {
  auto it = lua_callbacks_.find(type);
  if (it == lua_callbacks_.end() || !it->second.valid()) {
    return {};
  }

  try {
    auto result = it->second(vm, analysis, data);
    // for now, return empty vector - instruction rules require more complex handling
    return {};
  } catch (const sol::error& e) {
    logger_.err(
        "error in instr rule callback", redlog::field("type", static_cast<int>(type)), redlog::field("error", e.what())
    );
  }
  return {};
}

} // namespace w1::tracers::script