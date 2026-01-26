#include "callback_registry.hpp"

#include <algorithm>
#include <string_view>

#include "w1base/string_utils.hpp"
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

bool has_wildcards(std::string_view pattern) { return pattern.find_first_of("*?") != std::string_view::npos; }

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
  if (!entry.options.mnemonic.empty()) {
    entry.options.mnemonic = w1::util::to_lower(entry.options.mnemonic);
    entry.options.mnemonic_has_wildcards = has_wildcards(entry.options.mnemonic);
    mnemonic_filter_counts_[event_index(event)] += 1;
  }
  entry.callback = std::move(callback);

  callbacks_.emplace(entry.id, entry);
  if (dispatch_depth_ > 0) {
    pending_additions_.emplace_back(event, entry.id);
  } else {
    event_handlers_[event].push_back(entry.id);
  }

  return entry.id;
}

bool callback_registry::remove_callback(uint64_t handle) {
  auto it = callbacks_.find(handle);
  if (it == callbacks_.end()) {
    return false;
  }

  auto event = it->second.event;
  if (!it->second.options.mnemonic.empty()) {
    size_t index = event_index(event);
    if (mnemonic_filter_counts_[index] > 0) {
      mnemonic_filter_counts_[index] -= 1;
    }
  }

  callbacks_.erase(it);
  if (dispatch_depth_ > 0) {
    pending_prune_[event_index(event)] = true;
  } else {
    auto handler_it = event_handlers_.find(event);
    if (handler_it != event_handlers_.end()) {
      auto& list = handler_it->second;
      list.erase(std::remove(list.begin(), list.end(), handle), list.end());
    }
  }
  return true;
}

void callback_registry::shutdown() {
  callbacks_.clear();
  event_handlers_.clear();
  pending_additions_.clear();
  pending_prune_.fill(false);
  mnemonic_filter_counts_.fill(0);
  dispatch_depth_ = 0;
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
  dispatch_scope guard(*this);
  auto handler_it = event_handlers_.find(event_type);
  if (handler_it == event_handlers_.end()) {
    return QBDI::VMAction::CONTINUE;
  }

  const auto& handlers = handler_it->second;
  std::string mnemonic_lower;
  if (mnemonic_filter_counts_[event_index(event_type)] > 0 && vm) {
    const QBDI::InstAnalysis* analysis = vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION);
    if (analysis && analysis->mnemonic) {
      mnemonic_lower = w1::util::to_lower(analysis->mnemonic);
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
      if (mnemonic_lower.empty()) {
        continue;
      }
      if (entry.options.mnemonic_has_wildcards) {
        if (!is_mnemonic_match(entry.options.mnemonic, mnemonic_lower)) {
          continue;
        }
      } else if (entry.options.mnemonic != mnemonic_lower) {
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
  dispatch_scope guard(*this);
  auto handler_it = event_handlers_.find(event_type);
  if (handler_it == event_handlers_.end()) {
    return QBDI::VMAction::CONTINUE;
  }

  const auto& handlers = handler_it->second;
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
    event_type event_type, [[maybe_unused]] const w1::exec_transfer_event& event, QBDI::VMInstanceRef vm,
    const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  dispatch_scope guard(*this);
  auto handler_it = event_handlers_.find(event_type);
  if (handler_it == event_handlers_.end()) {
    return QBDI::VMAction::CONTINUE;
  }

  const auto& handlers = handler_it->second;
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
    event_type event_type, [[maybe_unused]] const w1::sequence_event& event, QBDI::VMInstanceRef vm,
    const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  dispatch_scope guard(*this);
  auto handler_it = event_handlers_.find(event_type);
  if (handler_it == event_handlers_.end()) {
    return QBDI::VMAction::CONTINUE;
  }

  const auto& handlers = handler_it->second;
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
  dispatch_scope guard(*this);
  auto handler_it = event_handlers_.find(event_type);
  if (handler_it == event_handlers_.end()) {
    return QBDI::VMAction::CONTINUE;
  }

  const auto& handlers = handler_it->second;
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
  dispatch_scope guard(*this);
  auto handler_it = event_handlers_.find(event_type);
  if (handler_it == event_handlers_.end()) {
    return QBDI::VMAction::CONTINUE;
  }

  const auto& handlers = handler_it->second;
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
  size_t p_index = 0;
  size_t m_index = 0;
  size_t star_index = std::string::npos;
  size_t match_index = 0;

  while (m_index < mnemonic.size()) {
    if (p_index < pattern.size() && (pattern[p_index] == mnemonic[m_index] || pattern[p_index] == '?')) {
      ++p_index;
      ++m_index;
      continue;
    }

    if (p_index < pattern.size() && pattern[p_index] == '*') {
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

  while (p_index < pattern.size() && pattern[p_index] == '*') {
    ++p_index;
  }

  return p_index == pattern.size();
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

void callback_registry::finish_dispatch() {
  if (dispatch_depth_ == 0) {
    return;
  }
  dispatch_depth_ -= 1;
  if (dispatch_depth_ == 0) {
    flush_pending();
  }
}

void callback_registry::flush_pending() {
  if (!pending_additions_.empty()) {
    for (const auto& entry : pending_additions_) {
      event_handlers_[entry.first].push_back(entry.second);
    }
    pending_additions_.clear();
  }

  for (size_t index = 0; index < pending_prune_.size(); ++index) {
    if (!pending_prune_[index]) {
      continue;
    }
    pending_prune_[index] = false;
    auto type = static_cast<event_type>(index);
    auto handler_it = event_handlers_.find(type);
    if (handler_it == event_handlers_.end()) {
      continue;
    }
    auto& handlers = handler_it->second;
    handlers.erase(
        std::remove_if(
            handlers.begin(), handlers.end(), [this](uint64_t id) { return callbacks_.find(id) == callbacks_.end(); }
        ),
        handlers.end()
    );
  }
}

} // namespace w1::tracers::script::runtime
