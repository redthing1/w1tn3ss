#include "callback_registry.hpp"

#include <algorithm>
#include <cctype>
#include <string_view>

namespace w1::tracers::script::runtime {
namespace {

sol::table build_state_table(sol::state_view lua, const QBDI::VMState* state) {
  sol::table out = lua.create_table();
  if (!state) {
    return out;
  }

  out["sequenceStart"] = static_cast<uint64_t>(state->sequenceStart);
  out["sequenceEnd"] = static_cast<uint64_t>(state->sequenceEnd);
  out["basicBlockStart"] = static_cast<uint64_t>(state->basicBlockStart);
  out["basicBlockEnd"] = static_cast<uint64_t>(state->basicBlockEnd);
  return out;
}

} // namespace

namespace {

std::string to_lower(std::string_view value) {
  std::string out(value.begin(), value.end());
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return out;
}

} // namespace

callback_registry::callback_registry() : logger_(redlog::get_logger("w1script.callbacks")) {}

uint64_t callback_registry::register_callback(
    event_type event, sol::protected_function callback, const registration_options& options
) {
  if (!callback.valid()) {
    return 0;
  }

  callback_entry entry;
  entry.id = next_id_++;
  entry.event = event;
  entry.options = options;
  entry.callback = std::move(callback);

  callbacks_.emplace(entry.id, entry);
  event_handlers_[event].push_back(entry.id);

  return entry.id;
}

bool callback_registry::remove_callback(uint64_t handle) {
  auto it = callbacks_.find(handle);
  if (it == callbacks_.end()) {
    return false;
  }

  auto event = it->second.event;
  auto handler_it = event_handlers_.find(event);
  if (handler_it != event_handlers_.end()) {
    auto& list = handler_it->second;
    list.erase(std::remove(list.begin(), list.end(), handle), list.end());
  }

  callbacks_.erase(it);
  return true;
}

void callback_registry::shutdown() {
  callbacks_.clear();
  event_handlers_.clear();
  next_id_ = 1;
}

QBDI::VMAction callback_registry::dispatch_thread_start(const w1::thread_event& event) {
  return dispatch_thread(event_type::thread_start, event);
}

QBDI::VMAction callback_registry::dispatch_thread_stop(const w1::thread_event& event) {
  return dispatch_thread(event_type::thread_stop, event);
}

QBDI::VMAction callback_registry::dispatch_vm_start(
    const w1::sequence_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  return dispatch_sequence(event_type::vm_start, event, vm, state, gpr, fpr);
}

QBDI::VMAction callback_registry::dispatch_vm_stop(
    const w1::sequence_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  return dispatch_sequence(event_type::vm_stop, event, vm, state, gpr, fpr);
}

QBDI::VMAction callback_registry::dispatch_instruction_pre(
    const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  return dispatch_instruction(event_type::instruction_pre, event, vm, gpr, fpr);
}

QBDI::VMAction callback_registry::dispatch_instruction_post(
    const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  return dispatch_instruction(event_type::instruction_post, event, vm, gpr, fpr);
}

QBDI::VMAction callback_registry::dispatch_basic_block_entry(
    const w1::basic_block_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  return dispatch_basic_block(event_type::basic_block_entry, event, vm, state, gpr, fpr);
}

QBDI::VMAction callback_registry::dispatch_basic_block_exit(
    const w1::basic_block_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  return dispatch_basic_block(event_type::basic_block_exit, event, vm, state, gpr, fpr);
}

QBDI::VMAction callback_registry::dispatch_exec_transfer_call(
    const w1::exec_transfer_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  return dispatch_exec_transfer(event_type::exec_transfer_call, event, vm, state, gpr, fpr);
}

QBDI::VMAction callback_registry::dispatch_exec_transfer_return(
    const w1::exec_transfer_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  return dispatch_exec_transfer(event_type::exec_transfer_return, event, vm, state, gpr, fpr);
}

QBDI::VMAction callback_registry::dispatch_memory(
    const w1::memory_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  if (event.is_read) {
    QBDI::VMAction action = dispatch_memory_event(event_type::memory_read, event, vm, gpr, fpr);
    if (action != QBDI::VMAction::CONTINUE) {
      return action;
    }
  }

  if (event.is_write) {
    QBDI::VMAction action = dispatch_memory_event(event_type::memory_write, event, vm, gpr, fpr);
    if (action != QBDI::VMAction::CONTINUE) {
      return action;
    }
  }

  if (event.is_read && event.is_write) {
    return dispatch_memory_event(event_type::memory_read_write, event, vm, gpr, fpr);
  }

  return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction callback_registry::dispatch_instruction(
    event_type event_type, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  auto handler_it = event_handlers_.find(event_type);
  if (handler_it == event_handlers_.end()) {
    return QBDI::VMAction::CONTINUE;
  }

  const QBDI::InstAnalysis* analysis = nullptr;
  std::string_view mnemonic;
  bool has_mnemonic_filter = false;

  auto handlers = handler_it->second;
  for (uint64_t id : handlers) {
    auto entry_it = callbacks_.find(id);
    if (entry_it == callbacks_.end()) {
      continue;
    }
    const auto& entry = entry_it->second;
    if (!entry.options.mnemonic.empty()) {
      has_mnemonic_filter = true;
      break;
    }
  }

  if (has_mnemonic_filter && vm) {
    analysis = vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION);
    if (analysis && analysis->mnemonic) {
      mnemonic = analysis->mnemonic;
    }
  }

  for (uint64_t id : handlers) {
    auto entry_it = callbacks_.find(id);
    if (entry_it == callbacks_.end()) {
      continue;
    }
    const auto& entry = entry_it->second;
    if (!matches_address(entry.options, event.address)) {
      continue;
    }

    if (!entry.options.mnemonic.empty()) {
      if (mnemonic.empty() || !is_mnemonic_match(entry.options.mnemonic, mnemonic)) {
        continue;
      }
    }

    auto result = entry.callback(vm, gpr, fpr);
    QBDI::VMAction action = resolve_action(result);
    if (action != QBDI::VMAction::CONTINUE) {
      return action;
    }
  }

  return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction callback_registry::dispatch_basic_block(
    event_type event_type, const w1::basic_block_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  auto handler_it = event_handlers_.find(event_type);
  if (handler_it == event_handlers_.end()) {
    return QBDI::VMAction::CONTINUE;
  }

  auto handlers = handler_it->second;
  for (uint64_t id : handlers) {
    auto entry_it = callbacks_.find(id);
    if (entry_it == callbacks_.end()) {
      continue;
    }
    const auto& entry = entry_it->second;
    if (!matches_address(entry.options, event.address)) {
      continue;
    }

    sol::state_view lua(entry.callback.lua_state());
    sol::table state_table = build_state_table(lua, state);
    auto result = entry.callback(vm, state_table, gpr, fpr);
    QBDI::VMAction action = resolve_action(result);
    if (action != QBDI::VMAction::CONTINUE) {
      return action;
    }
  }

  return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction callback_registry::dispatch_exec_transfer(
    event_type event_type, const w1::exec_transfer_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  auto handler_it = event_handlers_.find(event_type);
  if (handler_it == event_handlers_.end()) {
    return QBDI::VMAction::CONTINUE;
  }

  auto handlers = handler_it->second;
  for (uint64_t id : handlers) {
    auto entry_it = callbacks_.find(id);
    if (entry_it == callbacks_.end()) {
      continue;
    }
    const auto& entry = entry_it->second;
    sol::state_view lua(entry.callback.lua_state());
    sol::table state_table = build_state_table(lua, state);
    auto result = entry.callback(vm, state_table, gpr, fpr);
    QBDI::VMAction action = resolve_action(result);
    if (action != QBDI::VMAction::CONTINUE) {
      return action;
    }
  }

  return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction callback_registry::dispatch_sequence(
    event_type event_type, const w1::sequence_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  auto handler_it = event_handlers_.find(event_type);
  if (handler_it == event_handlers_.end()) {
    return QBDI::VMAction::CONTINUE;
  }

  auto handlers = handler_it->second;
  for (uint64_t id : handlers) {
    auto entry_it = callbacks_.find(id);
    if (entry_it == callbacks_.end()) {
      continue;
    }
    const auto& entry = entry_it->second;
    sol::state_view lua(entry.callback.lua_state());
    sol::table state_table = build_state_table(lua, state);
    auto result = entry.callback(vm, state_table, gpr, fpr);
    QBDI::VMAction action = resolve_action(result);
    if (action != QBDI::VMAction::CONTINUE) {
      return action;
    }
  }

  return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction callback_registry::dispatch_thread(event_type event_type, const w1::thread_event& event) {
  auto handler_it = event_handlers_.find(event_type);
  if (handler_it == event_handlers_.end()) {
    return QBDI::VMAction::CONTINUE;
  }

  auto handlers = handler_it->second;
  for (uint64_t id : handlers) {
    auto entry_it = callbacks_.find(id);
    if (entry_it == callbacks_.end()) {
      continue;
    }
    const auto& entry = entry_it->second;
    sol::state_view lua(entry.callback.lua_state());
    sol::table thread_info = lua.create_table();
    thread_info["thread_id"] = event.thread_id;
    thread_info["name"] = event.name ? event.name : "";

    auto result = entry.callback(thread_info);
    QBDI::VMAction action = resolve_action(result);
    if (action != QBDI::VMAction::CONTINUE) {
      return action;
    }
  }

  return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction callback_registry::dispatch_memory_event(
    event_type event_type, const w1::memory_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  auto handler_it = event_handlers_.find(event_type);
  if (handler_it == event_handlers_.end()) {
    return QBDI::VMAction::CONTINUE;
  }

  auto handlers = handler_it->second;
  for (uint64_t id : handlers) {
    auto entry_it = callbacks_.find(id);
    if (entry_it == callbacks_.end()) {
      continue;
    }
    const auto& entry = entry_it->second;
    if (!matches_address(entry.options, event.address)) {
      continue;
    }

    if (entry.options.access_type) {
      auto access_type = *entry.options.access_type;
      if ((access_type & QBDI::MEMORY_READ) != 0 && !event.is_read) {
        continue;
      }
      if ((access_type & QBDI::MEMORY_WRITE) != 0 && !event.is_write) {
        continue;
      }
    }

    sol::state_view lua(entry.callback.lua_state());
    sol::table access = lua.create_table();
    access["address"] = event.address;
    access["instruction_address"] = event.instruction_address;
    access["size"] = event.size;
    access["flags"] = event.flags;
    access["value"] = event.value_valid ? sol::make_object(lua, event.value) : sol::lua_nil;
    access["value_valid"] = event.value_valid;
    access["is_read"] = event.is_read;
    access["is_write"] = event.is_write;

    auto result = entry.callback(vm, gpr, fpr, access);
    QBDI::VMAction action = resolve_action(result);
    if (action != QBDI::VMAction::CONTINUE) {
      return action;
    }
  }

  return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction callback_registry::resolve_action(const sol::protected_function_result& result) {
  if (!result.valid()) {
    sol::error err = result;
    logger_.err("lua callback error", redlog::field("error", err.what()));
    return QBDI::VMAction::CONTINUE;
  }

  if (result.return_count() == 0) {
    return QBDI::VMAction::CONTINUE;
  }

  sol::object obj = result.get<sol::object>();
  if (obj.is<QBDI::VMAction>()) {
    return obj.as<QBDI::VMAction>();
  }
  if (obj.is<int>()) {
    return static_cast<QBDI::VMAction>(obj.as<int>());
  }
  if (obj.is<lua_Integer>()) {
    return static_cast<QBDI::VMAction>(obj.as<lua_Integer>());
  }

  return QBDI::VMAction::CONTINUE;
}

bool callback_registry::is_mnemonic_match(std::string_view pattern, std::string_view mnemonic) const {
  std::string p = to_lower(pattern);
  std::string m = to_lower(mnemonic);

  size_t p_index = 0;
  size_t m_index = 0;
  size_t star_index = std::string::npos;
  size_t match_index = 0;

  while (m_index < m.size()) {
    if (p_index < p.size() && (p[p_index] == m[m_index] || p[p_index] == '?')) {
      ++p_index;
      ++m_index;
      continue;
    }

    if (p_index < p.size() && p[p_index] == '*') {
      star_index = p_index++;
      match_index = m_index;
      continue;
    }

    if (star_index != std::string::npos) {
      p_index = star_index + 1;
      m_index = ++match_index;
      continue;
    }

    return false;
  }

  while (p_index < p.size() && p[p_index] == '*') {
    ++p_index;
  }

  return p_index == p.size();
}

bool callback_registry::matches_address(const registration_options& options, uint64_t address) const {
  if (options.address) {
    return address == *options.address;
  }

  if (options.start && options.end) {
    return address >= *options.start && address < *options.end;
  }

  return true;
}

} // namespace w1::tracers::script::runtime
