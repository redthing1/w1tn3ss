#pragma once

#include "callback_registry.hpp"
#include "script_context.hpp"

#include <sol/sol.hpp>
#include <redlog.hpp>

#include <string>

namespace w1::tracers::script::runtime {

class lua_runtime {
public:
  explicit lua_runtime(script_context& context);

  bool initialize();
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
  bool open_libraries();
  void configure_package_paths();
  bool register_bindings();
  bool load_script();
  bool call_init();

  script_context& context_;
  sol::state lua_;
  sol::table script_table_;
  callback_registry callback_registry_;
  redlog::logger logger_;
};

} // namespace w1::tracers::script::runtime
