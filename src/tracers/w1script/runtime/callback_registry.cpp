#include "callback_registry.hpp"

#include <algorithm>

namespace w1::tracers::script::runtime {

callback_registry::callback_registry(script_context& context, api_manager& api_manager)
    : context_(context), api_manager_(api_manager), logger_(redlog::get_logger("w1.script_callbacks")) {}

uint64_t callback_registry::register_callback(
    event_type event, sol::protected_function callback, const registration_options& options
) {
  callback_entry entry;
  entry.id = next_id_++;
  entry.event = event;
  entry.options = options;
  entry.callback = std::move(callback);

  callbacks_.emplace(entry.id, entry);

  switch (event) {
  case event_type::vm_start:
    event_handlers_[event].push_back(entry.id);
    break;
  case event_type::instruction_pre:
    event_handlers_[event].push_back(entry.id);
    ensure_event_enabled(event);
    break;
  case event_type::instruction_post:
    event_handlers_[event].push_back(entry.id);
    ensure_event_enabled(event);
    break;
  case event_type::sequence_entry:
  case event_type::sequence_exit:
  case event_type::basic_block_entry:
  case event_type::basic_block_exit:
  case event_type::basic_block_new:
  case event_type::exec_transfer_call:
  case event_type::exec_transfer_return:
  case event_type::syscall_entry:
  case event_type::syscall_exit:
  case event_type::signal:
    event_handlers_[event].push_back(entry.id);
    ensure_event_enabled(event);
    break;
  case event_type::memory_read:
  case event_type::memory_write:
  case event_type::memory_read_write:
    event_handlers_[event].push_back(entry.id);
    enable_memory_recording();
    ensure_event_enabled(event);
    break;
  case event_type::code_addr: {
    auto address = options.address.value_or(0);
    if (address == 0) {
      logger_.err("code_addr requires address option");
      callbacks_.erase(entry.id);
      return 0;
    }
    auto position = options.position.value_or(QBDI::PREINST);
    auto priority = options.priority.value_or(QBDI::PRIORITY_DEFAULT);

    uint32_t qbdi_id = context_.vm()->addCodeAddrCB(
        address, position,
        [this, id = entry.id](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr) -> QBDI::VMAction {
          return dispatch_single(id, vm, gpr, fpr);
        },
        priority
    );

    if (qbdi_id == QBDI::INVALID_EVENTID) {
      logger_.err("failed to register code_addr callback", redlog::field("address", "0x%lx", address));
      callbacks_.erase(entry.id);
      return 0;
    }

    callbacks_[entry.id].qbdi_id = qbdi_id;
    break;
  }
  case event_type::code_range: {
    auto start = options.start.value_or(0);
    auto end = options.end.value_or(0);
    if (start == 0 || end == 0 || start >= end) {
      logger_.err("code_range requires valid start and end options");
      callbacks_.erase(entry.id);
      return 0;
    }
    auto position = options.position.value_or(QBDI::PREINST);
    auto priority = options.priority.value_or(QBDI::PRIORITY_DEFAULT);

    uint32_t qbdi_id = context_.vm()->addCodeRangeCB(
        start, end, position,
        [this, id = entry.id](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr) -> QBDI::VMAction {
          return dispatch_single(id, vm, gpr, fpr);
        },
        priority
    );

    if (qbdi_id == QBDI::INVALID_EVENTID) {
      logger_.err("failed to register code_range callback", redlog::field("start", "0x%lx", start));
      callbacks_.erase(entry.id);
      return 0;
    }

    callbacks_[entry.id].qbdi_id = qbdi_id;
    break;
  }
  case event_type::mnemonic: {
    if (options.mnemonic.empty()) {
      logger_.err("mnemonic requires mnemonic option");
      callbacks_.erase(entry.id);
      return 0;
    }
    auto position = options.position.value_or(QBDI::PREINST);
    auto priority = options.priority.value_or(QBDI::PRIORITY_DEFAULT);

    uint32_t qbdi_id = context_.vm()->addMnemonicCB(
        options.mnemonic.c_str(), position,
        [this, id = entry.id](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr) -> QBDI::VMAction {
          return dispatch_single(id, vm, gpr, fpr);
        },
        priority
    );

    if (qbdi_id == QBDI::INVALID_EVENTID) {
      logger_.err("failed to register mnemonic callback", redlog::field("mnemonic", options.mnemonic));
      callbacks_.erase(entry.id);
      return 0;
    }

    callbacks_[entry.id].qbdi_id = qbdi_id;
    break;
  }
  case event_type::memory_addr: {
    auto address = options.address.value_or(0);
    if (address == 0) {
      logger_.err("memory_addr requires address option");
      callbacks_.erase(entry.id);
      return 0;
    }
    auto access = options.access_type.value_or(QBDI::MEMORY_READ_WRITE);
    enable_memory_recording();

    uint32_t qbdi_id = context_.vm()->addMemAddrCB(
        address, access,
        [this, id = entry.id](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr) -> QBDI::VMAction {
          return dispatch_single(id, vm, gpr, fpr);
        }
    );

    if (qbdi_id == QBDI::INVALID_EVENTID) {
      logger_.err("failed to register memory_addr callback", redlog::field("address", "0x%lx", address));
      callbacks_.erase(entry.id);
      return 0;
    }

    callbacks_[entry.id].qbdi_id = qbdi_id;
    break;
  }
  case event_type::memory_range: {
    auto start = options.start.value_or(0);
    auto end = options.end.value_or(0);
    if (start == 0 || end == 0 || start >= end) {
      logger_.err("memory_range requires valid start and end options");
      callbacks_.erase(entry.id);
      return 0;
    }
    auto access = options.access_type.value_or(QBDI::MEMORY_READ_WRITE);
    enable_memory_recording();

    uint32_t qbdi_id = context_.vm()->addMemRangeCB(
        start, end, access,
        [this, id = entry.id](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr) -> QBDI::VMAction {
          return dispatch_single(id, vm, gpr, fpr);
        }
    );

    if (qbdi_id == QBDI::INVALID_EVENTID) {
      logger_.err("failed to register memory_range callback", redlog::field("start", "0x%lx", start));
      callbacks_.erase(entry.id);
      return 0;
    }

    callbacks_[entry.id].qbdi_id = qbdi_id;
    break;
  }
  }

  return entry.id;
}

bool callback_registry::remove_callback(uint64_t handle) {
  auto it = callbacks_.find(handle);
  if (it == callbacks_.end()) {
    return false;
  }

  auto event = it->second.event;
  if (it->second.qbdi_id != QBDI::INVALID_EVENTID) {
    context_.vm()->deleteInstrumentation(it->second.qbdi_id);
  }

  auto handlers_it = event_handlers_.find(event);
  if (handlers_it != event_handlers_.end()) {
    auto& handlers = handlers_it->second;
    handlers.erase(std::remove(handlers.begin(), handlers.end(), handle), handlers.end());
    if (handlers.empty()) {
      auto qbdi_it = event_qbdi_ids_.find(event);
      if (qbdi_it != event_qbdi_ids_.end()) {
        context_.vm()->deleteInstrumentation(qbdi_it->second);
        event_qbdi_ids_.erase(qbdi_it);
      }
    }
  }

  callbacks_.erase(it);
  return true;
}

void callback_registry::shutdown() {
  for (const auto& [event, id] : event_qbdi_ids_) {
    context_.vm()->deleteInstrumentation(id);
  }
  event_qbdi_ids_.clear();
  event_handlers_.clear();

  for (const auto& [id, entry] : callbacks_) {
    if (entry.qbdi_id != QBDI::INVALID_EVENTID) {
      context_.vm()->deleteInstrumentation(entry.qbdi_id);
    }
  }

  callbacks_.clear();
}

QBDI::VMAction callback_registry::dispatch_vm_start(QBDI::VMInstanceRef vm) {
  auto it = event_handlers_.find(event_type::vm_start);
  if (it == event_handlers_.end()) {
    return QBDI::VMAction::CONTINUE;
  }

  for (auto id : it->second) {
    auto callback_it = callbacks_.find(id);
    if (callback_it == callbacks_.end()) {
      continue;
    }

    auto result = callback_it->second.callback(vm);
    if (!result.valid()) {
      sol::error err = result;
      logger_.err("error in vm_start callback", redlog::field("error", err.what()));
      continue;
    }

    QBDI::VMAction action = resolve_action(result);
    if (action != QBDI::VMAction::CONTINUE) {
      return action;
    }
  }

  return QBDI::VMAction::CONTINUE;
}

bool callback_registry::ensure_event_enabled(event_type event) {
  if (event_qbdi_ids_.find(event) != event_qbdi_ids_.end()) {
    return true;
  }

  switch (event) {
  case event_type::instruction_pre:
    return register_instruction_callback(event, QBDI::PREINST);
  case event_type::instruction_post:
    return register_instruction_callback(event, QBDI::POSTINST);
  case event_type::sequence_entry:
    return register_vm_event_callback(event, QBDI::SEQUENCE_ENTRY);
  case event_type::sequence_exit:
    return register_vm_event_callback(event, QBDI::SEQUENCE_EXIT);
  case event_type::basic_block_entry:
    return register_vm_event_callback(event, QBDI::BASIC_BLOCK_ENTRY);
  case event_type::basic_block_exit:
    return register_vm_event_callback(event, QBDI::BASIC_BLOCK_EXIT);
  case event_type::basic_block_new:
    return register_vm_event_callback(event, QBDI::BASIC_BLOCK_NEW);
  case event_type::exec_transfer_call:
    return register_vm_event_callback(event, QBDI::EXEC_TRANSFER_CALL);
  case event_type::exec_transfer_return:
    return register_vm_event_callback(event, QBDI::EXEC_TRANSFER_RETURN);
  case event_type::syscall_entry:
    return register_vm_event_callback(event, QBDI::SYSCALL_ENTRY);
  case event_type::syscall_exit:
    return register_vm_event_callback(event, QBDI::SYSCALL_EXIT);
  case event_type::signal:
    return register_vm_event_callback(event, QBDI::SIGNAL);
  case event_type::memory_read:
    return register_memory_callback(event, QBDI::MEMORY_READ);
  case event_type::memory_write:
    return register_memory_callback(event, QBDI::MEMORY_WRITE);
  case event_type::memory_read_write:
    return register_memory_callback(event, QBDI::MEMORY_READ_WRITE);
  case event_type::vm_start:
  case event_type::code_addr:
  case event_type::code_range:
  case event_type::mnemonic:
  case event_type::memory_addr:
  case event_type::memory_range:
    return true;
  }

  return false;
}

bool callback_registry::is_event_enabled(event_type event) const {
  return event_qbdi_ids_.find(event) != event_qbdi_ids_.end();
}

QBDI::VMAction callback_registry::dispatch_simple(
    event_type event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  auto it = event_handlers_.find(event);
  if (it == event_handlers_.end()) {
    return QBDI::VMAction::CONTINUE;
  }

  for (auto id : it->second) {
    auto callback_it = callbacks_.find(id);
    if (callback_it == callbacks_.end()) {
      continue;
    }

    auto result = callback_it->second.callback(vm, gpr, fpr);
    if (!result.valid()) {
      sol::error err = result;
      logger_.err("error in callback", redlog::field("error", err.what()));
      continue;
    }

    QBDI::VMAction action = resolve_action(result);
    if (action != QBDI::VMAction::CONTINUE) {
      return action;
    }
  }

  return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction callback_registry::dispatch_vm_event(
    event_type event, QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  if (event == event_type::exec_transfer_call) {
    api_manager_.process_call(context_.vm(), state, gpr, fpr);
  } else if (event == event_type::exec_transfer_return) {
    api_manager_.process_return(context_.vm(), state, gpr, fpr);
  }

  auto it = event_handlers_.find(event);
  if (it == event_handlers_.end()) {
    return QBDI::VMAction::CONTINUE;
  }

  for (auto id : it->second) {
    auto callback_it = callbacks_.find(id);
    if (callback_it == callbacks_.end()) {
      continue;
    }

    auto result = callback_it->second.callback(vm, *state, gpr, fpr);
    if (!result.valid()) {
      sol::error err = result;
      logger_.err("error in vm event callback", redlog::field("error", err.what()));
      continue;
    }

    QBDI::VMAction action = resolve_action(result);
    if (action != QBDI::VMAction::CONTINUE) {
      return action;
    }
  }

  return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction callback_registry::dispatch_single(
    uint64_t id, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  auto callback_it = callbacks_.find(id);
  if (callback_it == callbacks_.end()) {
    return QBDI::VMAction::CONTINUE;
  }

  auto result = callback_it->second.callback(vm, gpr, fpr);
  if (!result.valid()) {
    sol::error err = result;
    logger_.err("error in callback", redlog::field("error", err.what()));
    return QBDI::VMAction::CONTINUE;
  }

  return resolve_action(result);
}

void callback_registry::enable_memory_recording() {
  if (memory_recording_enabled_) {
    return;
  }

  memory_recording_enabled_ = context_.vm()->recordMemoryAccess(QBDI::MEMORY_READ_WRITE);
  if (!memory_recording_enabled_) {
    logger_.wrn("memory recording not supported on this platform");
  }
}

bool callback_registry::register_instruction_callback(event_type event, QBDI::InstPosition position) {
  uint32_t id = context_.vm()->addCodeCB(position, [this, event](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr) {
    return dispatch_simple(event, vm, gpr, fpr);
  });

  if (id == QBDI::INVALID_EVENTID) {
    logger_.err("failed to register instruction callback");
    return false;
  }

  event_qbdi_ids_[event] = id;
  return true;
}

bool callback_registry::register_vm_event_callback(event_type event, QBDI::VMEvent qbdi_event) {
  uint32_t id = context_.vm()->addVMEventCB(qbdi_event, [this, event](QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr) {
    return dispatch_vm_event(event, vm, state, gpr, fpr);
  });

  if (id == QBDI::INVALID_EVENTID) {
    logger_.err("failed to register vm event callback");
    return false;
  }

  event_qbdi_ids_[event] = id;
  return true;
}

bool callback_registry::register_memory_callback(event_type event, QBDI::MemoryAccessType type) {
  uint32_t id = context_.vm()->addMemAccessCB(type, [this, event](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr) {
    return dispatch_simple(event, vm, gpr, fpr);
  });

  if (id == QBDI::INVALID_EVENTID) {
    logger_.err("failed to register memory access callback");
    return false;
  }

  event_qbdi_ids_[event] = id;
  return true;
}

QBDI::VMAction callback_registry::resolve_action(const sol::protected_function_result& result) const {
  if (!result.valid()) {
    return QBDI::VMAction::CONTINUE;
  }

  sol::object obj = result;
  if (!obj.valid() || obj.is<sol::nil_t>()) {
    return QBDI::VMAction::CONTINUE;
  }

  if (obj.is<QBDI::VMAction>()) {
    return obj.as<QBDI::VMAction>();
  }

  if (obj.is<int>()) {
    return static_cast<QBDI::VMAction>(obj.as<int>());
  }

  if (obj.is<double>()) {
    return static_cast<QBDI::VMAction>(static_cast<int>(obj.as<double>()));
  }

  return QBDI::VMAction::CONTINUE;
}

} // namespace w1::tracers::script::runtime
