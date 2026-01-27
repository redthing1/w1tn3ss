#pragma once

#include "w1instrument/tracer/types.hpp"

#include <QBDI.h>
#include <redlog.hpp>
#include <sol/sol.hpp>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace w1::tracers::script::runtime {

class callback_registry {
public:
  enum class event_type : uint8_t {
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

  struct callback_filter {
    std::optional<uint64_t> address;
    std::optional<uint64_t> start;
    std::optional<uint64_t> end;
    std::optional<QBDI::MemoryAccessType> access_type;
    std::string mnemonic;
    bool mnemonic_has_wildcards = false;
  };

  using handle_t = uint64_t;

  callback_registry();

  handle_t register_callback(event_type event, sol::protected_function callback, const callback_filter& filter);
  bool remove_callback(handle_t handle);
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
  using slot_index = uint32_t;

  struct handle_parts {
    slot_index index = 0;
    uint32_t generation = 0;
  };

  struct dispatch_guard {
    explicit dispatch_guard(callback_registry& registry) : registry_(registry) { registry_.dispatch_depth_ += 1; }
    ~dispatch_guard() { registry_.finish_dispatch(); }

  private:
    callback_registry& registry_;
  };

  struct callback_slot {
    event_type event{};
    callback_filter filter{};
    sol::protected_function callback{};
    uint32_t generation = 1;
    bool active = false;
  };

  static constexpr size_t event_type_count = static_cast<size_t>(event_type::memory_read_write) + 1;
  static constexpr uint64_t handle_index_mask = 0xFFFFFFFFull;
  static constexpr uint32_t handle_index_bias = 1;

  static constexpr size_t event_index(event_type value) { return static_cast<size_t>(value); }

  handle_t make_handle(slot_index index, uint32_t generation) const;
  std::optional<handle_parts> parse_handle(handle_t handle) const;
  callback_slot* get_slot(slot_index index);
  const callback_slot* get_slot(slot_index index) const;
  slot_index allocate_slot();
  void release_slot(slot_index index);
  void add_handler(event_type event, slot_index index);
  bool has_mnemonic_filters(event_type event) const;

  template <typename FilterFn, typename InvokeFn>
  QBDI::VMAction dispatch_handlers(event_type event, FilterFn&& filter, InvokeFn&& invoke) {
    dispatch_guard guard(*this);
    auto& handlers = handlers_[event_index(event)];
    if (handlers.empty()) {
      return QBDI::VMAction::CONTINUE;
    }

    for (slot_index index : handlers) {
      callback_slot* slot = get_slot(index);
      if (!slot || !slot->active) {
        continue;
      }
      if (!filter(*slot)) {
        continue;
      }
      auto result = invoke(*slot);
      QBDI::VMAction action = resolve_action(result);
      if (action != QBDI::VMAction::CONTINUE) {
        return action;
      }
    }

    return QBDI::VMAction::CONTINUE;
  }

  QBDI::VMAction dispatch_instruction(
      event_type event, const w1::instruction_event& event_data, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  );
  QBDI::VMAction dispatch_basic_block(
      event_type event, const w1::basic_block_event& event_data, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );
  QBDI::VMAction dispatch_exec_transfer(
      event_type event, const w1::exec_transfer_event& event_data, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );
  QBDI::VMAction dispatch_sequence(
      event_type event, const w1::sequence_event& event_data, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
      QBDI::GPRState* gpr, QBDI::FPRState* fpr
  );
  QBDI::VMAction dispatch_thread(event_type event, const w1::thread_event& event_data);

  QBDI::VMAction dispatch_memory_event(
      event_type event, const w1::memory_event& event_data, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
      QBDI::FPRState* fpr
  );

  QBDI::VMAction resolve_action(const sol::protected_function_result& result);
  bool is_mnemonic_match(std::string_view pattern, std::string_view mnemonic) const;
  bool matches_address(const callback_filter& filter, uint64_t address) const;
  void finish_dispatch();
  void flush_pending();

  std::array<std::vector<slot_index>, event_type_count> handlers_{};
  std::vector<callback_slot> slots_{};
  std::vector<slot_index> free_list_{};
  std::vector<std::pair<event_type, slot_index>> pending_additions_{};
  std::vector<slot_index> pending_free_{};
  std::array<bool, event_type_count> pending_prune_{};
  std::array<size_t, event_type_count> mnemonic_filter_counts_{};
  size_t dispatch_depth_ = 0;
  redlog::logger logger_;
};

} // namespace w1::tracers::script::runtime
