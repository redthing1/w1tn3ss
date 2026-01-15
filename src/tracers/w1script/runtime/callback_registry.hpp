#pragma once

#include "w1tn3ss/tracer/types.hpp"

#include <QBDI.h>
#include <redlog.hpp>
#include <sol/sol.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace w1::tracers::script::runtime {

class callback_registry {
public:
  enum class event_type {
    thread_start,
    thread_stop,
    vm_start,
    vm_stop,
    instruction_pre,
    instruction_post,
    basic_block_entry,
    basic_block_exit,
    exec_transfer_call,
    exec_transfer_return,
    memory_read,
    memory_write,
    memory_read_write
  };

  struct registration_options {
    std::optional<uint64_t> address;
    std::optional<uint64_t> start;
    std::optional<uint64_t> end;
    std::optional<QBDI::MemoryAccessType> access_type;
    std::string mnemonic;
    bool mnemonic_has_wildcards = false;
  };

  callback_registry();

  uint64_t register_callback(event_type event, sol::protected_function callback, const registration_options& options);
  bool remove_callback(uint64_t handle);
  void shutdown();

  QBDI::VMAction dispatch_thread_start(const w1::thread_event& event);
  QBDI::VMAction dispatch_thread_stop(const w1::thread_event& event);

  QBDI::VMAction dispatch_vm_start(
      const w1::sequence_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  );
  QBDI::VMAction dispatch_vm_stop(
      const w1::sequence_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  );

  QBDI::VMAction dispatch_instruction_pre(
      const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );
  QBDI::VMAction dispatch_instruction_post(
      const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );

  QBDI::VMAction dispatch_basic_block_entry(
      const w1::basic_block_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  );
  QBDI::VMAction dispatch_basic_block_exit(
      const w1::basic_block_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  );

  QBDI::VMAction dispatch_exec_transfer_call(
      const w1::exec_transfer_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  );
  QBDI::VMAction dispatch_exec_transfer_return(
      const w1::exec_transfer_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  );

  QBDI::VMAction dispatch_memory(
      const w1::memory_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );

private:
  static constexpr size_t event_type_count = static_cast<size_t>(event_type::memory_read_write) + 1;

  static constexpr size_t event_index(event_type value) { return static_cast<size_t>(value); }

  struct dispatch_scope {
    explicit dispatch_scope(callback_registry& registry) : registry_(registry) { registry_.dispatch_depth_ += 1; }
    ~dispatch_scope() { registry_.finish_dispatch(); }

  private:
    callback_registry& registry_;
  };

  struct event_hash {
    size_t operator()(event_type value) const { return static_cast<size_t>(value); }
  };

  struct callback_entry {
    uint64_t id = 0;
    event_type event{};
    registration_options options{};
    sol::protected_function callback{};
  };

  QBDI::VMAction dispatch_instruction(
      event_type event_type, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  );
  QBDI::VMAction dispatch_basic_block(
      event_type event_type, const w1::basic_block_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );
  QBDI::VMAction dispatch_exec_transfer(
      event_type event_type, const w1::exec_transfer_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );
  QBDI::VMAction dispatch_sequence(
      event_type event_type, const w1::sequence_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );
  QBDI::VMAction dispatch_thread(event_type event_type, const w1::thread_event& event);

  QBDI::VMAction dispatch_memory_event(
      event_type event_type, const w1::memory_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  );

  QBDI::VMAction resolve_action(const sol::protected_function_result& result);
  bool is_mnemonic_match(std::string_view pattern, std::string_view mnemonic) const;
  bool matches_address(const registration_options& options, uint64_t address) const;
  void finish_dispatch();
  void flush_pending();

  uint64_t next_id_ = 1;
  std::unordered_map<uint64_t, callback_entry> callbacks_;
  std::unordered_map<event_type, std::vector<uint64_t>, event_hash> event_handlers_;
  std::vector<std::pair<event_type, uint64_t>> pending_additions_{};
  std::array<bool, event_type_count> pending_prune_{};
  std::array<size_t, event_type_count> mnemonic_filter_counts_{};
  size_t dispatch_depth_ = 0;
  redlog::logger logger_;
};

} // namespace w1::tracers::script::runtime
