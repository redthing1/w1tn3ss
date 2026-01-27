#include "callback_registry.hpp"

#include <algorithm>
#include <string_view>

#include "w1base/string_utils.hpp"

namespace w1::tracers::script::runtime {
namespace {

bool has_wildcards(std::string_view pattern) { return pattern.find_first_of("*?") != std::string_view::npos; }

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

callback_registry::callback_registry() : logger_(redlog::get_logger("w1script.callbacks")) {}

callback_registry::handle_t callback_registry::register_callback(
    event_type event, sol::protected_function callback, const callback_filter& filter
) {
  if (!callback.valid()) {
    return 0;
  }

  callback_filter stored_filter = filter;
  if (!stored_filter.mnemonic.empty()) {
    stored_filter.mnemonic = w1::util::to_lower(stored_filter.mnemonic);
    stored_filter.mnemonic_has_wildcards = has_wildcards(stored_filter.mnemonic);
    mnemonic_filter_counts_[event_index(event)] += 1;
  }

  slot_index index = allocate_slot();
  callback_slot& slot = slots_[index];
  slot.event = event;
  slot.filter = std::move(stored_filter);
  slot.callback = std::move(callback);
  slot.active = true;

  handle_t handle = make_handle(index, slot.generation);

  if (dispatch_depth_ > 0) {
    pending_additions_.emplace_back(event, index);
  } else {
    add_handler(event, index);
  }

  return handle;
}

bool callback_registry::remove_callback(handle_t handle) {
  auto parsed = parse_handle(handle);
  if (!parsed) {
    return false;
  }

  callback_slot* slot = get_slot(parsed->index);
  if (!slot || !slot->active || slot->generation != parsed->generation) {
    return false;
  }

  slot->active = false;
  if (!slot->filter.mnemonic.empty()) {
    size_t index = event_index(slot->event);
    if (mnemonic_filter_counts_[index] > 0) {
      mnemonic_filter_counts_[index] -= 1;
    }
  }

  if (dispatch_depth_ > 0) {
    pending_free_.push_back(parsed->index);
    pending_prune_[event_index(slot->event)] = true;
    return true;
  }

  auto& handlers = handlers_[event_index(slot->event)];
  handlers.erase(std::remove(handlers.begin(), handlers.end(), parsed->index), handlers.end());
  release_slot(parsed->index);
  return true;
}

void callback_registry::shutdown() {
  handlers_ = {};
  slots_.clear();
  free_list_.clear();
  pending_additions_.clear();
  pending_free_.clear();
  pending_prune_ = {};
  mnemonic_filter_counts_ = {};
  dispatch_depth_ = 0;
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

callback_registry::handle_t callback_registry::make_handle(slot_index index, uint32_t generation) const {
  return (static_cast<uint64_t>(generation) << 32) | (static_cast<uint64_t>(index) + handle_index_bias);
}

std::optional<callback_registry::handle_parts> callback_registry::parse_handle(handle_t handle) const {
  if (handle == 0) {
    return std::nullopt;
  }

  uint32_t raw_index = static_cast<uint32_t>(handle & handle_index_mask);
  if (raw_index < handle_index_bias) {
    return std::nullopt;
  }

  handle_parts parts;
  parts.index = raw_index - handle_index_bias;
  parts.generation = static_cast<uint32_t>(handle >> 32);
  return parts;
}

callback_registry::callback_slot* callback_registry::get_slot(slot_index index) {
  if (index >= slots_.size()) {
    return nullptr;
  }
  return &slots_[index];
}

const callback_registry::callback_slot* callback_registry::get_slot(slot_index index) const {
  if (index >= slots_.size()) {
    return nullptr;
  }
  return &slots_[index];
}

callback_registry::slot_index callback_registry::allocate_slot() {
  slot_index index = 0;
  if (!free_list_.empty()) {
    index = free_list_.back();
    free_list_.pop_back();
  } else {
    slots_.push_back(callback_slot{});
    index = static_cast<slot_index>(slots_.size() - 1);
  }

  callback_slot& slot = slots_[index];
  slot.event = event_type::thread_start;
  slot.filter = callback_filter{};
  slot.callback = sol::protected_function{};
  slot.active = false;
  if (slot.generation == 0) {
    slot.generation = 1;
  }

  return index;
}

void callback_registry::release_slot(slot_index index) {
  callback_slot* slot = get_slot(index);
  if (!slot) {
    return;
  }

  slot->callback = sol::protected_function{};
  slot->filter = callback_filter{};
  slot->event = event_type::thread_start;
  slot->active = false;
  slot->generation += 1;
  if (slot->generation == 0) {
    slot->generation = 1;
  }
  free_list_.push_back(index);
}

void callback_registry::add_handler(event_type event, slot_index index) {
  handlers_[event_index(event)].push_back(index);
}

bool callback_registry::has_mnemonic_filters(event_type event) const {
  return mnemonic_filter_counts_[event_index(event)] > 0;
}

QBDI::VMAction callback_registry::dispatch_instruction(
    event_type event, const w1::instruction_event& event_data, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  std::string mnemonic_lower;
  if (has_mnemonic_filters(event) && vm) {
    const QBDI::InstAnalysis* analysis = vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION);
    if (analysis && analysis->mnemonic) {
      mnemonic_lower = w1::util::to_lower(analysis->mnemonic);
    }
  }

  return dispatch_handlers(
      event,
      [&](const callback_slot& slot) {
        if (!matches_address(slot.filter, event_data.address)) {
          return false;
        }
        if (!slot.filter.mnemonic.empty()) {
          if (mnemonic_lower.empty()) {
            return false;
          }
          if (slot.filter.mnemonic_has_wildcards) {
            return is_mnemonic_match(slot.filter.mnemonic, mnemonic_lower);
          }
          return slot.filter.mnemonic == mnemonic_lower;
        }
        return true;
      },
      [&](callback_slot& slot) { return slot.callback(vm, gpr, fpr); }
  );
}

QBDI::VMAction callback_registry::dispatch_basic_block(
    event_type event, const w1::basic_block_event& event_data, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  return dispatch_handlers(
      event, [&](const callback_slot& slot) { return matches_address(slot.filter, event_data.address); },
      [&](callback_slot& slot) {
        sol::state_view lua(slot.callback.lua_state());
        sol::table state_table = build_state_table(lua, state);
        return slot.callback(vm, state_table, gpr, fpr);
      }
  );
}

QBDI::VMAction callback_registry::dispatch_exec_transfer(
    event_type event, const w1::exec_transfer_event&, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  return dispatch_handlers(
      event, [](const callback_slot&) { return true; },
      [&](callback_slot& slot) {
        sol::state_view lua(slot.callback.lua_state());
        sol::table state_table = build_state_table(lua, state);
        return slot.callback(vm, state_table, gpr, fpr);
      }
  );
}

QBDI::VMAction callback_registry::dispatch_sequence(
    event_type event, const w1::sequence_event&, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  return dispatch_handlers(
      event, [](const callback_slot&) { return true; },
      [&](callback_slot& slot) {
        sol::state_view lua(slot.callback.lua_state());
        sol::table state_table = build_state_table(lua, state);
        return slot.callback(vm, state_table, gpr, fpr);
      }
  );
}

QBDI::VMAction callback_registry::dispatch_thread(event_type event, const w1::thread_event& event_data) {
  return dispatch_handlers(
      event, [](const callback_slot&) { return true; },
      [&](callback_slot& slot) {
        sol::state_view lua(slot.callback.lua_state());
        sol::table thread_info = lua.create_table();
        thread_info["thread_id"] = event_data.thread_id;
        thread_info["name"] = event_data.name ? event_data.name : "";
        return slot.callback(thread_info);
      }
  );
}

QBDI::VMAction callback_registry::dispatch_memory_event(
    event_type event, const w1::memory_event& event_data, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  return dispatch_handlers(
      event,
      [&](const callback_slot& slot) {
        if (!matches_address(slot.filter, event_data.address)) {
          return false;
        }
        if (slot.filter.access_type) {
          auto access_type = *slot.filter.access_type;
          if ((access_type & QBDI::MEMORY_READ) != 0 && !event_data.is_read) {
            return false;
          }
          if ((access_type & QBDI::MEMORY_WRITE) != 0 && !event_data.is_write) {
            return false;
          }
        }
        return true;
      },
      [&](callback_slot& slot) {
        sol::state_view lua(slot.callback.lua_state());
        sol::table access = lua.create_table();
        access["address"] = event_data.address;
        access["instruction_address"] = event_data.instruction_address;
        access["size"] = event_data.size;
        access["flags"] = event_data.flags;
        access["value"] = event_data.value_valid ? sol::make_object(lua, event_data.value) : sol::lua_nil;
        access["value_valid"] = event_data.value_valid;
        access["is_read"] = event_data.is_read;
        access["is_write"] = event_data.is_write;
        return slot.callback(vm, gpr, fpr, access);
      }
  );
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
      star_index = p_index;
      match_index = m_index;
      ++p_index;
      continue;
    }

    if (star_index != std::string::npos) {
      p_index = star_index + 1;
      ++match_index;
      m_index = match_index;
      continue;
    }

    return false;
  }

  while (p_index < pattern.size() && pattern[p_index] == '*') {
    ++p_index;
  }

  return p_index == pattern.size();
}

bool callback_registry::matches_address(const callback_filter& filter, uint64_t address) const {
  if (filter.address) {
    return address == *filter.address;
  }

  if (filter.start && filter.end) {
    return address >= *filter.start && address < *filter.end;
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
      add_handler(entry.first, entry.second);
    }
    pending_additions_.clear();
  }

  for (size_t index = 0; index < pending_prune_.size(); ++index) {
    if (!pending_prune_[index]) {
      continue;
    }
    pending_prune_[index] = false;

    auto& handlers = handlers_[index];
    handlers.erase(
        std::remove_if(
            handlers.begin(), handlers.end(),
            [&](slot_index slot_id) {
              const callback_slot* slot = get_slot(slot_id);
              if (!slot) {
                return true;
              }
              if (!slot->active) {
                return true;
              }
              return event_index(slot->event) != index;
            }
        ),
        handlers.end()
    );
  }

  if (!pending_free_.empty()) {
    for (slot_index index : pending_free_) {
      release_slot(index);
    }
    pending_free_.clear();
  }
}

} // namespace w1::tracers::script::runtime
