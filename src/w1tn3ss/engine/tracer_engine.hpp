#pragma once

#include <functional>
#include <iostream>
#include <type_traits>

#include <QBDI.h>
#include <redlog/redlog.hpp>

namespace w1 {

template <typename TTracer> class tracer_engine {
public:
  tracer_engine(QBDI::VMInstanceRef vm, TTracer& tracer)
      : vm_(static_cast<QBDI::VM*>(vm)), tracer_(tracer), owns_vm_(false) {
    log_.inf(
        "tracer engine created with existing QBDI::VM instance", redlog::field("tracer", tracer.get_name()),
        redlog::field("vm", static_cast<void*>(vm_))
    );
  }

  tracer_engine(TTracer& tracer) : tracer_(tracer), owns_vm_(true) {
    try {
      vm_ = new QBDI::VM();
      log_.inf("tracer engine created with new vm", redlog::field("tracer_name", tracer.get_name()));
    } catch (...) {
      vm_ = nullptr;
      owns_vm_ = false;
      log_.error("failed to create QBDI::VM instance, tracer engine will not function");
      // re-throw the exception to be handled by the caller
      throw;
    }
  }

public:
  ~tracer_engine() {
    if (owns_vm_ && vm_) {
      delete vm_;
    }
  }

  bool instrument() {
    if (!vm_) {
      log_.error("QBDI::VM instance is null, cannot instrument");
      return false;
    }

    register_all_callbacks();
    return true;
  }

  bool run(QBDI::rword start, QBDI::rword stop) {
    if (!vm_) {
      log_.error("QBDI::VM instance is null, cannot run");
      return false;
    }

    log_.inf(
        "executing QBDI::VM::run", redlog::field("tracer", tracer_.get_name()), redlog::field("start", "0x%08x", start),
        redlog::field("stop", "0x%08x", stop)
    );
    return vm_->run(start, stop);
  }

  bool call(QBDI::rword* retval, QBDI::rword function_ptr, const std::vector<QBDI::rword>& args) {
    if (!vm_) {
      return false;
    }

    log_.inf(
        "executing QBDI::VM::call", redlog::field("tracer", tracer_.get_name()),
        redlog::field("function_ptr", "0x%08x", function_ptr), redlog::field("args", args)
    );
    return vm_->call(retval, function_ptr, args);
  }

  QBDI::VM* get_vm() const { return vm_; }

private:
  QBDI::VM* vm_;
  TTracer& tracer_;
  bool owns_vm_;
  redlog::logger log_ = redlog::get_logger("w1tn3ss.tracer_engine");

  // - SFINAE detection for callback methods (C++17)

  // -- SFINAE queries

  template <typename T, typename = void> struct has_instruction_preinst_callback : std::false_type {};
  template <typename T>
  struct has_instruction_preinst_callback<
      T, std::void_t<decltype(std::declval<T>().on_instruction_preinst(
             std::declval<QBDI::VMInstanceRef>(), std::declval<QBDI::GPRState*>(), std::declval<QBDI::FPRState*>()
         ))>> : std::true_type {};

  template <typename T, typename = void> struct has_basic_block_entry_callback : std::false_type {};
  template <typename T>
  struct has_basic_block_entry_callback<
      T, std::void_t<decltype(std::declval<T>().on_basic_block_entry(
             std::declval<QBDI::VMInstanceRef>(), std::declval<const QBDI::VMState*>(), std::declval<QBDI::GPRState*>(),
             std::declval<QBDI::FPRState*>()
         ))>> : std::true_type {};

  // -- SFINAE results

  template <typename T>
  static constexpr bool has_instruction_preinst_callback_v = has_instruction_preinst_callback<T>::value;

  template <typename T>
  static constexpr bool has_basic_block_entry_callback_v = has_basic_block_entry_callback<T>::value;

  // - Callback registration methods

  void register_instruction_callback() {
    if constexpr (has_instruction_preinst_callback_v<TTracer>) {
      log_.vrb("registering callback", redlog::field("callback", "INSTRUCTION_PREINST"));

      uint32_t id = vm_->addCodeCB(
          QBDI::PREINST,
          [](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data) -> QBDI::VMAction {
            auto* engine = static_cast<tracer_engine<TTracer>*>(data);
            return engine->tracer_.on_instruction_preinst(vm, gpr, fpr);
          },
          this
      );

      if (id != QBDI::INVALID_EVENTID) {
        log_.inf("registered callback", redlog::field("callback", "INSTRUCTION_PREINST"), redlog::field("id", id));
      } else {
        log_.error(
            "failed to register callback", redlog::field("callback", "INSTRUCTION_PREINST"), redlog::field("id", id)
        );
      }
    } else {
      log_.trc("not requested", redlog::field("callback", "INSTRUCTION_PREINST"));
    }
  }

  void register_basic_block_entry_callback() {
    if constexpr (has_basic_block_entry_callback_v<TTracer>) {
      log_.vrb("registering callback", redlog::field("callback", "BASIC_BLOCK_ENTRY"));

      uint32_t id = vm_->addVMEventCB(
          QBDI::BASIC_BLOCK_ENTRY,
          [](QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr,
             void* data) -> QBDI::VMAction {
            auto* engine = static_cast<tracer_engine<TTracer>*>(data);
            return engine->tracer_.on_basic_block_entry(vm, state, gpr, fpr);
          },
          this
      );

      if (id != QBDI::INVALID_EVENTID) {
        log_.inf("registered callback", redlog::field("callback", "BASIC_BLOCK_ENTRY"), redlog::field("id", id));
      } else {
        log_.error(
            "failed to register callback", redlog::field("callback", "BASIC_BLOCK_ENTRY"), redlog::field("id", id)
        );
      }
    } else {
      log_.trc("not requested", redlog::field("callback", "BASIC_BLOCK_ENTRY"));
    }
  }

  void register_all_callbacks() {
    log_.inf("registering callbacks...");
    //   register_instruction_callback();
    //   register_instruction_with_state_callback();
    //   register_sequence_entry_callback();
    //   register_sequence_exit_callback();
    //   register_basic_block_entry_callback();
    //   register_basic_block_exit_callback();
    //   register_basic_block_new_callback();
    //   register_exec_transfer_call_callback();
    //   register_exec_transfer_return_callback();
    //   register_syscall_entry_callback();
    //   register_syscall_exit_callback();

    // TODO: support the other callbacks

    register_instruction_callback();
    register_basic_block_entry_callback();

    log_.inf("callback registration complete");
  }
};

} // namespace w1
