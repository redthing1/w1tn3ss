#pragma once

#include "api_manager.hpp"
#include "script_context.hpp"

#include <sol/sol.hpp>

#include <QBDI.h>
#include <redlog.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace w1::tracers::script::runtime {

class callback_registry {
public:
  enum class event_type {
    vm_start,
    instruction_pre,
    instruction_post,
    sequence_entry,
    sequence_exit,
    basic_block_entry,
    basic_block_exit,
    basic_block_new,
    exec_transfer_call,
    exec_transfer_return,
    syscall_entry,
    syscall_exit,
    signal,
    memory_read,
    memory_write,
    memory_read_write,
    code_addr,
    code_range,
    mnemonic,
    memory_addr,
    memory_range
  };

  struct registration_options {
    std::optional<QBDI::rword> address;
    std::optional<QBDI::rword> start;
    std::optional<QBDI::rword> end;
    std::optional<QBDI::InstPosition> position;
    std::optional<QBDI::MemoryAccessType> access_type;
    std::optional<int> priority;
    std::string mnemonic;
  };

  callback_registry(script_context& context, api_manager& api_manager);

  uint64_t register_callback(event_type event, sol::protected_function callback, const registration_options& options);
  bool remove_callback(uint64_t handle);
  void shutdown();

  QBDI::VMAction dispatch_vm_start(QBDI::VMInstanceRef vm);

  bool ensure_event_enabled(event_type event);
  bool is_event_enabled(event_type event) const;

private:
  struct callback_entry {
    uint64_t id = 0;
    event_type event;
    registration_options options;
    sol::protected_function callback;
    uint32_t qbdi_id = QBDI::INVALID_EVENTID;
  };

  QBDI::VMAction dispatch_simple(event_type event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr);
  QBDI::VMAction dispatch_vm_event(
      event_type event, QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );
  QBDI::VMAction dispatch_single(uint64_t id, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr);

  void enable_memory_recording();

  bool register_instruction_callback(event_type event, QBDI::InstPosition position);
  bool register_vm_event_callback(event_type event, QBDI::VMEvent qbdi_event);
  bool register_memory_callback(event_type event, QBDI::MemoryAccessType type);

  QBDI::VMAction resolve_action(const sol::protected_function_result& result) const;

  script_context& context_;
  api_manager& api_manager_;
  redlog::logger logger_;

  uint64_t next_id_ = 1;
  bool memory_recording_enabled_ = false;

  std::unordered_map<uint64_t, callback_entry> callbacks_;
  std::unordered_map<event_type, std::vector<uint64_t>> event_handlers_;
  std::unordered_map<event_type, uint32_t> event_qbdi_ids_;
};

} // namespace w1::tracers::script::runtime
