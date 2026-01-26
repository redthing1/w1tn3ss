#include "darwin_internal.hpp"
#include <signal.h>

namespace w1::debugger::darwin {

darwin_session::darwin_session(pid pid, mach_port_t task) : task_port(task), target_pid(pid) {
  // detect architecture
#ifdef __arm64__
  target_arch = arch::arm64;
#elif __x86_64__
  target_arch = arch::x86_64;
#else
  target_arch = arch::x86;
#endif
}

darwin_session::~darwin_session() {
  if (exception_port != MACH_PORT_NULL) {
    mach_port_deallocate(mach_task_self(), exception_port);
  }
  if (task_port != MACH_PORT_NULL) {
    mach_port_deallocate(mach_task_self(), task_port);
  }
}

result darwin_session::detach() {
  // detach from process
  if (task_port != MACH_PORT_NULL) {
    kern_return_t kr = mach_port_deallocate(mach_task_self(), task_port);
    if (kr != KERN_SUCCESS) {
      return make_error_result(error_code::operation_failed, "failed to detach", kr);
    }
    task_port = MACH_PORT_NULL;
  }
  return make_success_result();
}

result darwin_session::kill() {
  // send sigkill to process
  if (::kill(target_pid.native, SIGKILL) != 0) {
    return make_error_result(error_code::operation_failed, "failed to kill process", errno);
  }
  return make_success_result();
}

pid darwin_session::get_pid() const { return target_pid; }

arch darwin_session::get_arch() const { return target_arch; }

capabilities darwin_session::get_capabilities() const {
  capabilities caps;
  caps.hardware_breakpoints = true;
  caps.watchpoints = true;
  caps.remote_allocation = true;
  caps.thread_suspension = true;
  caps.single_stepping = true;
  return caps;
}

result darwin_session::get_threads(std::vector<tid>& out_threads) const {
  thread_array_t thread_list;
  mach_msg_type_number_t thread_count;

  kern_return_t kr = task_threads(task_port, &thread_list, &thread_count);
  if (kr != KERN_SUCCESS) {
    return make_error_result(error_code::operation_failed, "failed to get threads", kr);
  }

  out_threads.clear();
  for (mach_msg_type_number_t i = 0; i < thread_count; i++) {
    out_threads.push_back(tid{static_cast<uint64_t>(thread_list[i])});
    mach_port_deallocate(mach_task_self(), thread_list[i]);
  }

  vm_deallocate(mach_task_self(), (vm_address_t) thread_list, thread_count * sizeof(thread_t));
  return make_success_result();
}

result darwin_session::suspend_thread(tid thread_id) { return suspend_thread_impl(thread_id); }

result darwin_session::resume_thread(tid thread_id) { return resume_thread_impl(thread_id); }

result darwin_session::continue_execution() {
  // resume the entire task (all threads)
  kern_return_t kr = task_resume(task_port);
  if (kr != KERN_SUCCESS) {
    return make_error_result(error_code::operation_failed, "failed to resume task", kr);
  }
  return make_success_result();
}

result darwin_session::single_step(tid thread_id) { return single_step_impl(thread_id); }

result darwin_session::get_registers(tid thread_id, register_context& out_regs) const {
  return get_registers_impl(thread_id, out_regs);
}

result darwin_session::set_registers(tid thread_id, const register_context& regs) {
  return set_registers_impl(thread_id, regs);
}

result darwin_session::read_memory(addr address, size_t size, std::vector<uint8_t>& out_data) const {
  return read_memory_impl(task_port, address, size, out_data);
}

result darwin_session::write_memory(addr address, const std::vector<uint8_t>& data) {
  return write_memory_impl(task_port, address, data);
}

result darwin_session::get_memory_regions(std::vector<memory_region>& out_regions) const {
  return get_memory_regions_impl(task_port, out_regions);
}

result darwin_session::allocate_memory(size_t size, memory_prot prot, addr& out_address) {
  return allocate_memory_impl(task_port, size, prot, out_address);
}

result darwin_session::protect_memory(addr address, size_t size, memory_prot prot) {
  return protect_memory_impl(task_port, address, size, prot);
}

result darwin_session::wait_for_event(debug_event& out_event, std::optional<std::chrono::milliseconds> timeout) {
  (void) out_event;
  (void) timeout;
  return make_error_result(error_code::not_implemented);
}

result darwin_session::set_breakpoint(addr address) {
  (void) address;
  return make_error_result(error_code::not_implemented);
}

result darwin_session::remove_breakpoint(addr address) {
  (void) address;
  return make_error_result(error_code::not_implemented);
}

} // namespace w1::debugger::darwin
