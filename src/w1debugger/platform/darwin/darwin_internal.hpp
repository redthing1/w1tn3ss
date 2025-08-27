#pragma once

#include "../../w1debugger.hpp"
#include "../../session_impl.hpp"

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/thread_state.h>

namespace w1::debugger::darwin {

// debug session impl for darwin
class darwin_session : public session_impl {
private:
  mach_port_t task_port = MACH_PORT_NULL;
  pid target_pid;
  arch target_arch;
  mach_port_t exception_port = MACH_PORT_NULL;

public:
  darwin_session(pid pid, mach_port_t task);
  ~darwin_session() override;

  result detach() override;
  result kill() override;
  pid get_pid() const override;
  arch get_arch() const override;
  capabilities get_capabilities() const override;

  result get_threads(std::vector<tid>& out_threads) const override;
  result suspend_thread(tid thread_id) override;
  result resume_thread(tid thread_id) override;
  result continue_execution() override;
  result single_step(tid thread_id) override;

  result get_registers(tid thread_id, register_context& out_regs) const override;
  result set_registers(tid thread_id, const register_context& regs) override;

  result read_memory(addr address, size_t size, std::vector<uint8_t>& out_data) const override;
  result write_memory(addr address, const std::vector<uint8_t>& data) override;
  result get_memory_regions(std::vector<memory_region>& out_regions) const override;
  result allocate_memory(size_t size, memory_prot prot, addr& out_address) override;
  result protect_memory(addr address, size_t size, memory_prot prot) override;

  result wait_for_event(debug_event& out_event, std::optional<std::chrono::milliseconds> timeout) override;
  result set_breakpoint(addr address) override;
  result remove_breakpoint(addr address) override;
};

// entitlement checking
bool check_has_debugger_entitlement();

// process control operations
std::unique_ptr<session> session_attach(pid target_pid, const config& cfg, result& out_result);
std::unique_ptr<session> session_launch(const std::string& path, const config& cfg, result& out_result);
std::vector<process_info> list_processes();
bool check_debugger_capability();

// memory operations
result read_memory_impl(mach_port_t task_port, addr address, size_t size, std::vector<uint8_t>& out_data);
result write_memory_impl(mach_port_t task_port, addr address, const std::vector<uint8_t>& data);
result get_memory_regions_impl(mach_port_t task_port, std::vector<memory_region>& out_regions);
result allocate_memory_impl(mach_port_t task_port, size_t size, memory_prot prot, addr& out_address);
result protect_memory_impl(mach_port_t task_port, addr address, size_t size, memory_prot prot);

// thread context operations
result get_registers_impl(tid thread_id, register_context& out_regs);
result set_registers_impl(tid thread_id, const register_context& regs);
result single_step_impl(tid thread_id);
result suspend_thread_impl(tid thread_id);
result resume_thread_impl(tid thread_id);

} // namespace w1::debugger::darwin
