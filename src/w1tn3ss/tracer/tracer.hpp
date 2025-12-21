#pragma once

#include <concepts>
#include <type_traits>

#include <QBDI.h>

#include "w1tn3ss/tracer/event.hpp"
#include "w1tn3ss/tracer/types.hpp"

namespace w1 {

class trace_context;

template <typename result_t>
concept handler_result = std::same_as<result_t, void> || std::same_as<result_t, QBDI::VMAction>;

template <typename t>
concept tracer = requires(t& value) {
  { value.name() } -> std::same_as<const char*>;
  { t::requested_events() } -> std::same_as<event_mask>;
};

template <typename t>
concept has_on_instruction_pre = requires(
    t& value, trace_context& ctx, const instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  { value.on_instruction_pre(ctx, event, vm, gpr, fpr) } -> handler_result;
};

template <typename t>
concept has_on_instruction_post = requires(
    t& value, trace_context& ctx, const instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  { value.on_instruction_post(ctx, event, vm, gpr, fpr) } -> handler_result;
};

template <typename t>
concept has_on_basic_block_entry = requires(
    t& value, trace_context& ctx, const basic_block_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  { value.on_basic_block_entry(ctx, event, vm, state, gpr, fpr) } -> handler_result;
};

template <typename t>
concept has_on_basic_block_exit = requires(
    t& value, trace_context& ctx, const basic_block_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  { value.on_basic_block_exit(ctx, event, vm, state, gpr, fpr) } -> handler_result;
};

template <typename t>
concept has_on_exec_transfer_call = requires(
    t& value, trace_context& ctx, const exec_transfer_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  { value.on_exec_transfer_call(ctx, event, vm, state, gpr, fpr) } -> handler_result;
};

template <typename t>
concept has_on_exec_transfer_return = requires(
    t& value, trace_context& ctx, const exec_transfer_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  { value.on_exec_transfer_return(ctx, event, vm, state, gpr, fpr) } -> handler_result;
};

template <typename t>
concept has_on_vm_start = requires(
    t& value, trace_context& ctx, const sequence_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  { value.on_vm_start(ctx, event, vm, state, gpr, fpr) } -> handler_result;
};

template <typename t>
concept has_on_vm_stop = requires(
    t& value, trace_context& ctx, const sequence_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  { value.on_vm_stop(ctx, event, vm, state, gpr, fpr) } -> handler_result;
};

template <typename t>
concept has_on_memory = requires(
    t& value, trace_context& ctx, const memory_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  { value.on_memory(ctx, event, vm, gpr, fpr) } -> handler_result;
};

template <typename t>
concept has_on_thread_start = requires(t& value, trace_context& ctx, const thread_event& event) {
  { value.on_thread_start(ctx, event) } -> handler_result;
};

template <typename t>
concept has_on_thread_stop = requires(t& value, trace_context& ctx, const thread_event& event) {
  { value.on_thread_stop(ctx, event) } -> handler_result;
};

template <typename t>
constexpr void validate_tracer() {
  static_assert(tracer<t>, "tracer must define name() and static requested_events()");
  constexpr event_mask mask = t::requested_events();

  if constexpr (event_mask_has(mask, event_kind::instruction_pre)) {
    static_assert(has_on_instruction_pre<t>, "tracer requests instruction_pre but lacks on_instruction_pre");
  }
  if constexpr (event_mask_has(mask, event_kind::instruction_post)) {
    static_assert(has_on_instruction_post<t>, "tracer requests instruction_post but lacks on_instruction_post");
  }
  if constexpr (event_mask_has(mask, event_kind::basic_block_entry)) {
    static_assert(has_on_basic_block_entry<t>, "tracer requests basic_block_entry but lacks on_basic_block_entry");
  }
  if constexpr (event_mask_has(mask, event_kind::basic_block_exit)) {
    static_assert(has_on_basic_block_exit<t>, "tracer requests basic_block_exit but lacks on_basic_block_exit");
  }
  if constexpr (event_mask_has(mask, event_kind::exec_transfer_call)) {
    static_assert(has_on_exec_transfer_call<t>, "tracer requests exec_transfer_call but lacks on_exec_transfer_call");
  }
  if constexpr (event_mask_has(mask, event_kind::exec_transfer_return)) {
    static_assert(has_on_exec_transfer_return<t>, "tracer requests exec_transfer_return but lacks on_exec_transfer_return");
  }
  if constexpr (event_mask_has(mask, event_kind::vm_start)) {
    static_assert(has_on_vm_start<t>, "tracer requests vm_start but lacks on_vm_start");
  }
  if constexpr (event_mask_has(mask, event_kind::vm_stop)) {
    static_assert(has_on_vm_stop<t>, "tracer requests vm_stop but lacks on_vm_stop");
  }
  if constexpr (event_mask_has(mask, event_kind::memory_read) || event_mask_has(mask, event_kind::memory_write) ||
                event_mask_has(mask, event_kind::memory_read_write)) {
    static_assert(has_on_memory<t>, "tracer requests memory events but lacks on_memory");
  }
  if constexpr (event_mask_has(mask, event_kind::thread_start)) {
    static_assert(has_on_thread_start<t>, "tracer requests thread_start but lacks on_thread_start");
  }
  if constexpr (event_mask_has(mask, event_kind::thread_stop)) {
    static_assert(has_on_thread_stop<t>, "tracer requests thread_stop but lacks on_thread_stop");
  }
}

} // namespace w1
