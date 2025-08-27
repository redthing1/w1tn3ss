#include "darwin_internal.hpp"
#include <mach/arm/thread_state.h>
#include <mach/arm/thread_status.h>
#include <mach/i386/thread_state.h>

namespace w1::debugger::darwin {

result get_registers_impl(tid thread_id, register_context& out_regs) {
#ifdef __arm64__
  // arm64 implementation
  arm_thread_state64_t state;
  mach_msg_type_number_t state_count = ARM_THREAD_STATE64_COUNT;

  kern_return_t kr = thread_get_state(
      static_cast<thread_t>(thread_id.native), ARM_THREAD_STATE64, (thread_state_t) &state, &state_count
  );

  if (kr != KERN_SUCCESS) {
    return make_error_result(error_code::operation_failed, "failed to get thread state", kr);
  }

  // map to our arm64_regs structure
  arm64_regs regs;
  for (int i = 0; i < 29; i++) {
    regs.x[i] = state.__x[i];
  }
  regs.x[29] = state.__fp; // frame pointer
  regs.x[30] = state.__lr; // link register
  regs.sp = state.__sp;
  regs.pc = state.__pc;
  regs.pstate = state.__cpsr;

  out_regs = regs;
  return make_success_result();
#elif __x86_64__
  // x86_64 implementation
  x86_thread_state64_t state;
  mach_msg_type_number_t state_count = x86_THREAD_STATE64_COUNT;

  kern_return_t kr = thread_get_state(
      static_cast<thread_t>(thread_id.native), x86_THREAD_STATE64, (thread_state_t) &state, &state_count
  );

  if (kr != KERN_SUCCESS) {
    return make_error_result(error_code::operation_failed, "failed to get thread state", kr);
  }

  // map to our x64_regs structure
  x64_regs regs;
  regs.rax = state.__rax;
  regs.rbx = state.__rbx;
  regs.rcx = state.__rcx;
  regs.rdx = state.__rdx;
  regs.rsi = state.__rsi;
  regs.rdi = state.__rdi;
  regs.rbp = state.__rbp;
  regs.rsp = state.__rsp;
  regs.r8 = state.__r8;
  regs.r9 = state.__r9;
  regs.r10 = state.__r10;
  regs.r11 = state.__r11;
  regs.r12 = state.__r12;
  regs.r13 = state.__r13;
  regs.r14 = state.__r14;
  regs.r15 = state.__r15;
  regs.rip = state.__rip;
  regs.rflags = state.__rflags;

  out_regs = regs;
  return make_success_result();
#else
  return make_error_result(error_code::not_implemented, "unsupported architecture");
#endif
}

result set_registers_impl(tid thread_id, const register_context& regs) {
#ifdef __arm64__
  // arm64 implementation
  if (!std::holds_alternative<arm64_regs>(regs)) {
    return make_error_result(error_code::invalid_state, "wrong register type for architecture");
  }

  const auto& arm_regs = std::get<arm64_regs>(regs);
  arm_thread_state64_t state;

  // populate state from our structure
  for (int i = 0; i < 29; i++) {
    state.__x[i] = arm_regs.x[i];
  }
  state.__fp = arm_regs.x[29]; // frame pointer
  state.__lr = arm_regs.x[30]; // link register
  state.__sp = arm_regs.sp;
  state.__pc = arm_regs.pc;
  state.__cpsr = arm_regs.pstate;

  kern_return_t kr = thread_set_state(
      static_cast<thread_t>(thread_id.native), ARM_THREAD_STATE64, (thread_state_t) &state, ARM_THREAD_STATE64_COUNT
  );

  if (kr != KERN_SUCCESS) {
    return make_error_result(error_code::operation_failed, "failed to set thread state", kr);
  }

  return make_success_result();
#elif __x86_64__
  // x86_64 implementation
  if (!std::holds_alternative<x64_regs>(regs)) {
    return make_error_result(error_code::invalid_state, "wrong register type for architecture");
  }

  const auto& x64_regs_val = std::get<x64_regs>(regs);
  x86_thread_state64_t state;

  // populate state from our structure
  state.__rax = x64_regs_val.rax;
  state.__rbx = x64_regs_val.rbx;
  state.__rcx = x64_regs_val.rcx;
  state.__rdx = x64_regs_val.rdx;
  state.__rsi = x64_regs_val.rsi;
  state.__rdi = x64_regs_val.rdi;
  state.__rbp = x64_regs_val.rbp;
  state.__rsp = x64_regs_val.rsp;
  state.__r8 = x64_regs_val.r8;
  state.__r9 = x64_regs_val.r9;
  state.__r10 = x64_regs_val.r10;
  state.__r11 = x64_regs_val.r11;
  state.__r12 = x64_regs_val.r12;
  state.__r13 = x64_regs_val.r13;
  state.__r14 = x64_regs_val.r14;
  state.__r15 = x64_regs_val.r15;
  state.__rip = x64_regs_val.rip;
  state.__rflags = x64_regs_val.rflags;

  kern_return_t kr = thread_set_state(
      static_cast<thread_t>(thread_id.native), x86_THREAD_STATE64, (thread_state_t) &state, x86_THREAD_STATE64_COUNT
  );

  if (kr != KERN_SUCCESS) {
    return make_error_result(error_code::operation_failed, "failed to set thread state", kr);
  }

  return make_success_result();
#else
  return make_error_result(error_code::not_implemented, "unsupported architecture");
#endif
}

result single_step_impl(tid thread_id) {
#ifdef __arm64__
  // arm64: use debug state to enable single stepping
  arm_debug_state64_t debug_state;
  mach_msg_type_number_t debug_state_count = ARM_DEBUG_STATE64_COUNT;

  // get current debug state
  kern_return_t kr = thread_get_state(
      static_cast<thread_t>(thread_id.native), ARM_DEBUG_STATE64, (thread_state_t) &debug_state, &debug_state_count
  );

  if (kr != KERN_SUCCESS) {
    return make_error_result(error_code::operation_failed, "failed to get debug state", kr);
  }

  // enable single step in mdscr_el1
  debug_state.__mdscr_el1 |= 1; // set SS bit (bit 0)

  // set the modified state
  kr = thread_set_state(
      static_cast<thread_t>(thread_id.native), ARM_DEBUG_STATE64, (thread_state_t) &debug_state, ARM_DEBUG_STATE64_COUNT
  );

  if (kr != KERN_SUCCESS) {
    return make_error_result(error_code::operation_failed, "failed to set debug state", kr);
  }

  // resume the thread to execute one instruction
  kr = thread_resume(static_cast<thread_t>(thread_id.native));
  if (kr != KERN_SUCCESS) {
    return make_error_result(error_code::operation_failed, "failed to resume thread for single step", kr);
  }

  return make_success_result();
#else
  // x86_64: use rflags trap flag
  x86_thread_state64_t state;
  mach_msg_type_number_t state_count = x86_THREAD_STATE64_COUNT;

  kern_return_t kr = thread_get_state(
      static_cast<thread_t>(thread_id.native), x86_THREAD_STATE64, (thread_state_t) &state, &state_count
  );

  if (kr != KERN_SUCCESS) {
    return make_error_result(error_code::operation_failed, "failed to get thread state", kr);
  }

  // set trap flag (bit 8) in rflags
  state.__rflags |= 0x100;

  kr = thread_set_state(
      static_cast<thread_t>(thread_id.native), x86_THREAD_STATE64, (thread_state_t) &state, x86_THREAD_STATE64_COUNT
  );

  if (kr != KERN_SUCCESS) {
    return make_error_result(error_code::operation_failed, "failed to set thread state", kr);
  }

  // resume the thread
  kr = thread_resume(static_cast<thread_t>(thread_id.native));
  if (kr != KERN_SUCCESS) {
    return make_error_result(error_code::operation_failed, "failed to resume thread for single step", kr);
  }

  return make_success_result();
#endif
}

result suspend_thread_impl(tid thread_id) {
  kern_return_t kr = thread_suspend(static_cast<thread_t>(thread_id.native));
  if (kr != KERN_SUCCESS) {
    return make_error_result(error_code::operation_failed, "failed to suspend thread", kr);
  }
  return make_success_result();
}

result resume_thread_impl(tid thread_id) {
  kern_return_t kr = thread_resume(static_cast<thread_t>(thread_id.native));
  if (kr != KERN_SUCCESS) {
    return make_error_result(error_code::operation_failed, "failed to resume thread", kr);
  }
  return make_success_result();
}

} // namespace w1::debugger::darwin
