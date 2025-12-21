#pragma once

#include <cstddef>
#include <initializer_list>
#include <memory>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

#include <QBDI.h>
#include <redlog.hpp>

namespace w1::gadget {

enum class instrumentation_scope {
  inherit,
  range,
  module,
  all_executable
};

struct gadget_result {
  bool success = false;
  std::string error;
  QBDI::GPRState gpr{};
  QBDI::FPRState fpr{};
  size_t instruction_count = 0;
  QBDI::rword stop_address = 0;
};

struct call_options {
  instrumentation_scope scope = instrumentation_scope::inherit;
  size_t stack_size = 0;
  size_t range_size = 0;
  size_t max_instructions = 0;
};

struct run_options {
  instrumentation_scope scope = instrumentation_scope::inherit;
  size_t stack_size = 0;
  size_t range_size = 0;
  size_t max_instructions = 0;
};

class gadget_executor {
public:
  static constexpr size_t default_stack_size = 0x10000;
  static constexpr size_t default_range_size = 0x10000;

  struct config {
    bool debug;
    size_t stack_size;
    size_t call_range_size;
    size_t run_range_size;
    size_t max_instructions;
    instrumentation_scope call_scope;
    instrumentation_scope run_scope;

    constexpr config()
        : debug(false),
          stack_size(default_stack_size),
          call_range_size(default_range_size),
          run_range_size(default_range_size),
          max_instructions(0),
          call_scope(instrumentation_scope::module),
          run_scope(instrumentation_scope::range) {}
  };

  explicit gadget_executor(QBDI::VM* parent_vm, config cfg = config{});

  gadget_executor(const gadget_executor&) = delete;
  gadget_executor& operator=(const gadget_executor&) = delete;
  gadget_executor(gadget_executor&&) = delete;
  gadget_executor& operator=(gadget_executor&&) = delete;

  template <typename RetType = QBDI::rword>
  RetType gadget_call(QBDI::rword addr, std::span<const QBDI::rword> args = {}, call_options options = {});

  template <typename RetType = QBDI::rword>
  RetType gadget_call(QBDI::rword addr, std::initializer_list<QBDI::rword> args, call_options options = {});

  gadget_result gadget_run(QBDI::rword start_addr, QBDI::rword stop_addr, run_options options = {});

  std::unique_ptr<QBDI::VM> create_sub_vm();

  gadget_result run_with_vm(QBDI::VM* vm, QBDI::rword start_addr, QBDI::rword stop_addr);

private:
  struct stack_guard {
    uint8_t* stack = nullptr;

    stack_guard() = default;
    stack_guard(const stack_guard&) = delete;
    stack_guard& operator=(const stack_guard&) = delete;
    ~stack_guard();

    bool allocate(QBDI::GPRState* gpr, size_t stack_size);
  };

  struct stop_state {
    QBDI::rword stop_addr = 0;
    size_t max_instructions = 0;
    size_t instruction_count = 0;
    QBDI::rword stop_pc = 0;
  };

  void setup_debug_callback(QBDI::VM* vm);
  bool configure_instrumentation(
      QBDI::VM* vm, instrumentation_scope scope, QBDI::rword start_addr, QBDI::rword stop_addr, size_t range_size,
      std::string* error
  );
  bool prepare_vm_state(QBDI::VM* vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, size_t stack_size, stack_guard& stack);
  bool install_stop_callback(QBDI::VM* vm, stop_state& state);
  bool execute_call(
      QBDI::rword addr, std::span<const QBDI::rword> args, const call_options& options, QBDI::rword* result,
      std::string* error
  );

  instrumentation_scope resolve_scope(instrumentation_scope requested, instrumentation_scope fallback) const;
  size_t resolve_stack_size(size_t requested) const;
  size_t resolve_range_size(size_t requested, size_t fallback) const;
  size_t resolve_max_instructions(size_t requested) const;

  QBDI::VM* parent_vm_ = nullptr;
  config config_{};
};

template <typename RetType>
RetType gadget_executor::gadget_call(QBDI::rword addr, std::span<const QBDI::rword> args, call_options options) {
  auto log = redlog::get_logger("w1.gadget.executor");
  QBDI::rword result = 0;
  std::string error;
  bool success = execute_call(addr, args, options, &result, &error);

  if (!success) {
    log.err("gadget call failed", redlog::field("addr", "0x%llx", addr), redlog::field("error", error));
    if constexpr (std::is_same_v<RetType, void>) {
      return;
    } else {
      return RetType{};
    }
  }

  log.dbg("gadget call succeeded", redlog::field("addr", "0x%llx", addr));
  if constexpr (std::is_same_v<RetType, void>) {
    return;
  } else {
    return static_cast<RetType>(result);
  }
}

template <typename RetType>
RetType gadget_executor::gadget_call(QBDI::rword addr, std::initializer_list<QBDI::rword> args, call_options options) {
  return gadget_call<RetType>(addr, std::span<const QBDI::rword>(args.begin(), args.size()), options);
}

} // namespace w1::gadget
