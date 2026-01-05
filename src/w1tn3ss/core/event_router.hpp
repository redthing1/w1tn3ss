#pragma once

#include <concepts>
#include <cstdint>
#include <type_traits>
#include <vector>

#include <QBDI.h>

#include "w1tn3ss/tracer/event.hpp"
#include "w1tn3ss/tracer/trace_context.hpp"
#include "w1tn3ss/tracer/tracer.hpp"
#include "w1tn3ss/tracer/types.hpp"

namespace w1::core {

template <tracer tracer_t> class event_router {
public:
  explicit event_router(QBDI::VM* vm) : vm_(vm) {}

  event_router(const event_router&) = delete;
  event_router& operator=(const event_router&) = delete;
  event_router(event_router&&) = delete;
  event_router& operator=(event_router&&) = delete;

  ~event_router() { clear(); }

  bool configure(event_mask mask, tracer_t& tracer_instance, trace_context& ctx) {
    if (!vm_) {
      return false;
    }

    clear();
    state_.tracer = &tracer_instance;
    state_.ctx = &ctx;
    state_.mask = mask;
    state_.memory_recording_enabled = false;
    state_.memory_recording_requested = false;

    bool ok = true;
    const bool wants_postinst = event_mask_has(mask, event_kind::instruction_post);
    const bool wants_memory = event_mask_has(mask, event_kind::memory_read) ||
                              event_mask_has(mask, event_kind::memory_write) ||
                              event_mask_has(mask, event_kind::memory_read_write);

    if (wants_memory) {
      state_.memory_recording_requested = true;
      if (!enable_memory_recording()) {
        ok = false;
      }
    }

    if (event_mask_has(mask, event_kind::instruction_pre)) {
      if constexpr (has_on_instruction_pre<tracer_t>) {
        uint32_t id = vm_->addCodeCB(
            QBDI::PREINST,
            [](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data) -> QBDI::VMAction {
              auto* state = static_cast<callback_state*>(data);
              const QBDI::InstAnalysis* inst = vm->getInstAnalysis(QBDI::AnalysisType::ANALYSIS_INSTRUCTION);

              instruction_event event{};
              event.address = inst ? inst->address : QBDI_GPR_GET(gpr, QBDI::REG_PC);
              event.size = inst ? inst->instSize : 0;
              event.thread_id = state->ctx->thread_id();

              if constexpr (std::same_as<
                                decltype(state->tracer->on_instruction_pre(*state->ctx, event, vm, gpr, fpr)),
                                QBDI::VMAction>) {
                return state->tracer->on_instruction_pre(*state->ctx, event, vm, gpr, fpr);
              }
              state->tracer->on_instruction_pre(*state->ctx, event, vm, gpr, fpr);
              return QBDI::VMAction::CONTINUE;
            },
            &state_
        );

        if (id != QBDI::INVALID_EVENTID) {
          callback_ids_.push_back(id);
        } else {
          ok = false;
        }
      } else {
        ok = false;
      }
    }

    if (wants_postinst) {
      if constexpr (!has_on_instruction_post<tracer_t>) {
        ok = false;
      }
    }

    if (wants_memory) {
      if constexpr (!has_on_memory<tracer_t>) {
        ok = false;
      }
    }

    if ((wants_postinst || wants_memory) && ok) {
      uint32_t id = vm_->addCodeCB(
          QBDI::POSTINST,
          [](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data) -> QBDI::VMAction {
            auto* state = static_cast<callback_state*>(data);
            const bool postinst_enabled = event_mask_has(state->mask, event_kind::instruction_post);
            const bool memory_enabled = event_mask_has(state->mask, event_kind::memory_read) ||
                                        event_mask_has(state->mask, event_kind::memory_write) ||
                                        event_mask_has(state->mask, event_kind::memory_read_write);

            const QBDI::InstAnalysis* inst = nullptr;
            uint64_t inst_addr = 0;
            uint32_t inst_size = 0;
            if (postinst_enabled || memory_enabled) {
              inst = vm->getInstAnalysis(QBDI::AnalysisType::ANALYSIS_INSTRUCTION);
              if (inst) {
                inst_addr = inst->address;
                inst_size = inst->instSize;
              }
            }

            if constexpr (has_on_instruction_post<tracer_t>) {
              if (postinst_enabled) {
                instruction_event event{};
                event.address = inst_addr != 0 ? inst_addr : QBDI_GPR_GET(gpr, QBDI::REG_PC);
                event.size = inst_size;
                event.thread_id = state->ctx->thread_id();

                if constexpr (std::same_as<
                                  decltype(state->tracer->on_instruction_post(*state->ctx, event, vm, gpr, fpr)),
                                  QBDI::VMAction>) {
                  QBDI::VMAction action = state->tracer->on_instruction_post(*state->ctx, event, vm, gpr, fpr);
                  if (action != QBDI::VMAction::CONTINUE) {
                    return action;
                  }
                } else {
                  state->tracer->on_instruction_post(*state->ctx, event, vm, gpr, fpr);
                }
              }
            }

            if constexpr (has_on_memory<tracer_t>) {
              if (memory_enabled && state->memory_recording_enabled) {
                bool wants_read = event_mask_has(state->mask, event_kind::memory_read);
                bool wants_write = event_mask_has(state->mask, event_kind::memory_write);
                bool wants_read_write = event_mask_has(state->mask, event_kind::memory_read_write);

                auto accesses = vm->getInstMemoryAccess();
                for (const auto& access : accesses) {
                  bool is_read = (access.type & QBDI::MEMORY_READ) != 0;
                  bool is_write = (access.type & QBDI::MEMORY_WRITE) != 0;

                  if ((is_read && wants_read) || (is_write && wants_write) ||
                      ((is_read && is_write) && wants_read_write)) {
                    memory_event event{};
                    event.instruction_address = access.instAddress != 0 ? access.instAddress : inst_addr;
                    event.address = access.accessAddress;
                    event.size = access.size;
                    event.flags = static_cast<uint32_t>(access.flags);
                    event.value = (access.flags & QBDI::MEMORY_UNKNOWN_VALUE) ? 0 : access.value;
                    event.is_read = is_read;
                    event.is_write = is_write;
                    event.value_valid = (access.flags & QBDI::MEMORY_UNKNOWN_VALUE) == 0;
                    event.thread_id = state->ctx->thread_id();

                    if constexpr (std::same_as<
                                      decltype(state->tracer->on_memory(*state->ctx, event, vm, gpr, fpr)),
                                      QBDI::VMAction>) {
                      QBDI::VMAction action = state->tracer->on_memory(*state->ctx, event, vm, gpr, fpr);
                      if (action != QBDI::VMAction::CONTINUE) {
                        return action;
                      }
                    } else {
                      state->tracer->on_memory(*state->ctx, event, vm, gpr, fpr);
                    }
                  }
                }
              }
            }

            return QBDI::VMAction::CONTINUE;
          },
          &state_
      );

      if (id != QBDI::INVALID_EVENTID) {
        callback_ids_.push_back(id);
      } else {
        ok = false;
      }
    }

    if (event_mask_has(mask, event_kind::basic_block_entry)) {
      if constexpr (has_on_basic_block_entry<tracer_t>) {
        uint32_t id = vm_->addVMEventCB(
            QBDI::BASIC_BLOCK_ENTRY,
            [](QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr,
               void* data) -> QBDI::VMAction {
              auto* callback = static_cast<callback_state*>(data);
              uint64_t start = state ? state->basicBlockStart : 0;
              uint64_t end = state ? state->basicBlockEnd : start;

              basic_block_event event{};
              event.address = start;
              event.size = end > start ? static_cast<uint32_t>(end - start) : 0;
              event.thread_id = callback->ctx->thread_id();

              if constexpr (std::same_as<
                                decltype(callback->tracer
                                             ->on_basic_block_entry(*callback->ctx, event, vm, state, gpr, fpr)),
                                QBDI::VMAction>) {
                return callback->tracer->on_basic_block_entry(*callback->ctx, event, vm, state, gpr, fpr);
              }
              callback->tracer->on_basic_block_entry(*callback->ctx, event, vm, state, gpr, fpr);
              return QBDI::VMAction::CONTINUE;
            },
            &state_
        );

        if (id != QBDI::INVALID_EVENTID) {
          callback_ids_.push_back(id);
        } else {
          ok = false;
        }
      } else {
        ok = false;
      }
    }

    if (event_mask_has(mask, event_kind::basic_block_exit)) {
      if constexpr (has_on_basic_block_exit<tracer_t>) {
        uint32_t id = vm_->addVMEventCB(
            QBDI::BASIC_BLOCK_EXIT,
            [](QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr,
               void* data) -> QBDI::VMAction {
              auto* callback = static_cast<callback_state*>(data);
              uint64_t start = state ? state->basicBlockStart : 0;
              uint64_t end = state ? state->basicBlockEnd : start;

              basic_block_event event{};
              event.address = start;
              event.size = end > start ? static_cast<uint32_t>(end - start) : 0;
              event.thread_id = callback->ctx->thread_id();

              if constexpr (std::same_as<
                                decltype(callback->tracer
                                             ->on_basic_block_exit(*callback->ctx, event, vm, state, gpr, fpr)),
                                QBDI::VMAction>) {
                return callback->tracer->on_basic_block_exit(*callback->ctx, event, vm, state, gpr, fpr);
              }
              callback->tracer->on_basic_block_exit(*callback->ctx, event, vm, state, gpr, fpr);
              return QBDI::VMAction::CONTINUE;
            },
            &state_
        );

        if (id != QBDI::INVALID_EVENTID) {
          callback_ids_.push_back(id);
        } else {
          ok = false;
        }
      } else {
        ok = false;
      }
    }

    if (event_mask_has(mask, event_kind::exec_transfer_call)) {
      if constexpr (has_on_exec_transfer_call<tracer_t>) {
        uint32_t id = vm_->addVMEventCB(
            QBDI::EXEC_TRANSFER_CALL,
            [](QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr,
               void* data) -> QBDI::VMAction {
              auto* callback = static_cast<callback_state*>(data);
              uint64_t source = state ? state->sequenceStart : 0;
              uint64_t target = gpr ? QBDI_GPR_GET(gpr, QBDI::REG_PC) : 0;

              exec_transfer_event event{};
              event.source_address = source;
              event.target_address = target;
              event.thread_id = callback->ctx->thread_id();

              if constexpr (std::same_as<
                                decltype(callback->tracer
                                             ->on_exec_transfer_call(*callback->ctx, event, vm, state, gpr, fpr)),
                                QBDI::VMAction>) {
                return callback->tracer->on_exec_transfer_call(*callback->ctx, event, vm, state, gpr, fpr);
              }
              callback->tracer->on_exec_transfer_call(*callback->ctx, event, vm, state, gpr, fpr);
              return QBDI::VMAction::CONTINUE;
            },
            &state_
        );

        if (id != QBDI::INVALID_EVENTID) {
          callback_ids_.push_back(id);
        } else {
          ok = false;
        }
      } else {
        ok = false;
      }
    }

    if (event_mask_has(mask, event_kind::exec_transfer_return)) {
      if constexpr (has_on_exec_transfer_return<tracer_t>) {
        uint32_t id = vm_->addVMEventCB(
            QBDI::EXEC_TRANSFER_RETURN,
            [](QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr,
               void* data) -> QBDI::VMAction {
              auto* callback = static_cast<callback_state*>(data);
              uint64_t source = state ? state->sequenceStart : 0;
              uint64_t target = gpr ? QBDI_GPR_GET(gpr, QBDI::REG_PC) : 0;

              exec_transfer_event event{};
              event.source_address = source;
              event.target_address = target;
              event.thread_id = callback->ctx->thread_id();

              if constexpr (std::same_as<
                                decltype(callback->tracer
                                             ->on_exec_transfer_return(*callback->ctx, event, vm, state, gpr, fpr)),
                                QBDI::VMAction>) {
                return callback->tracer->on_exec_transfer_return(*callback->ctx, event, vm, state, gpr, fpr);
              }
              callback->tracer->on_exec_transfer_return(*callback->ctx, event, vm, state, gpr, fpr);
              return QBDI::VMAction::CONTINUE;
            },
            &state_
        );

        if (id != QBDI::INVALID_EVENTID) {
          callback_ids_.push_back(id);
        } else {
          ok = false;
        }
      } else {
        ok = false;
      }
    }

    if (event_mask_has(mask, event_kind::vm_start)) {
      if constexpr (has_on_vm_start<tracer_t>) {
        uint32_t id = vm_->addVMEventCB(
            QBDI::SEQUENCE_ENTRY,
            [](QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr,
               void* data) -> QBDI::VMAction {
              auto* callback = static_cast<callback_state*>(data);
              uint64_t start = state ? state->sequenceStart : 0;
              uint64_t end = state ? state->sequenceEnd : start;

              sequence_event event{};
              event.start = start;
              event.end = end;
              event.thread_id = callback->ctx->thread_id();

              if constexpr (std::same_as<
                                decltype(callback->tracer->on_vm_start(*callback->ctx, event, vm, state, gpr, fpr)),
                                QBDI::VMAction>) {
                return callback->tracer->on_vm_start(*callback->ctx, event, vm, state, gpr, fpr);
              }
              callback->tracer->on_vm_start(*callback->ctx, event, vm, state, gpr, fpr);
              return QBDI::VMAction::CONTINUE;
            },
            &state_
        );

        if (id != QBDI::INVALID_EVENTID) {
          callback_ids_.push_back(id);
        } else {
          ok = false;
        }
      } else {
        ok = false;
      }
    }

    if (event_mask_has(mask, event_kind::vm_stop)) {
      if constexpr (has_on_vm_stop<tracer_t>) {
        uint32_t id = vm_->addVMEventCB(
            QBDI::SEQUENCE_EXIT,
            [](QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr,
               void* data) -> QBDI::VMAction {
              auto* callback = static_cast<callback_state*>(data);
              uint64_t start = state ? state->sequenceStart : 0;
              uint64_t end = state ? state->sequenceEnd : start;

              sequence_event event{};
              event.start = start;
              event.end = end;
              event.thread_id = callback->ctx->thread_id();

              if constexpr (std::same_as<
                                decltype(callback->tracer->on_vm_stop(*callback->ctx, event, vm, state, gpr, fpr)),
                                QBDI::VMAction>) {
                return callback->tracer->on_vm_stop(*callback->ctx, event, vm, state, gpr, fpr);
              }
              callback->tracer->on_vm_stop(*callback->ctx, event, vm, state, gpr, fpr);
              return QBDI::VMAction::CONTINUE;
            },
            &state_
        );

        if (id != QBDI::INVALID_EVENTID) {
          callback_ids_.push_back(id);
        } else {
          ok = false;
        }
      } else {
        ok = false;
      }
    }

    if (!ok) {
      clear();
      return false;
    }

    return true;
  }

  void clear() {
    if (vm_) {
      for (uint32_t id : callback_ids_) {
        vm_->deleteInstrumentation(id);
      }
    }
    callback_ids_.clear();
    state_ = {};
  }

  void detach() {
    callback_ids_.clear();
    state_ = {};
    vm_ = nullptr;
  }

  bool enable_memory_recording() {
    if (!vm_ || !state_.memory_recording_requested) {
      return true;
    }
    if (state_.memory_recording_enabled) {
      return true;
    }

    QBDI::MemoryAccessType type = static_cast<QBDI::MemoryAccessType>(0);
    if (event_mask_has(state_.mask, event_kind::memory_read) ||
        event_mask_has(state_.mask, event_kind::memory_read_write)) {
      type = static_cast<QBDI::MemoryAccessType>(type | QBDI::MEMORY_READ);
    }
    if (event_mask_has(state_.mask, event_kind::memory_write) ||
        event_mask_has(state_.mask, event_kind::memory_read_write)) {
      type = static_cast<QBDI::MemoryAccessType>(type | QBDI::MEMORY_WRITE);
    }
    if (type == static_cast<QBDI::MemoryAccessType>(0)) {
      return true;
    }

    state_.memory_recording_enabled = vm_->recordMemoryAccess(type);
    return state_.memory_recording_enabled;
  }

private:
  struct callback_state {
    tracer_t* tracer = nullptr;
    trace_context* ctx = nullptr;
    event_mask mask = 0;
    bool memory_recording_requested = false;
    bool memory_recording_enabled = false;
  };

  QBDI::VM* vm_ = nullptr;
  callback_state state_{};
  std::vector<uint32_t> callback_ids_{};
};

} // namespace w1::core
