#pragma once

#include "types.hpp"
#include "error.hpp"

#include <memory>

namespace w1::debugger {

// forward decl
class session_impl;

// main debugger session class
class session {
public:
  static std::unique_ptr<session> attach(pid target_pid, const config& cfg, result& out_result);
  static std::unique_ptr<session> launch(const std::string& path, const config& cfg, result& out_result);

  ~session();

  // control
  result detach();
  result kill();
  result continue_execution();

  // process info
  pid get_pid() const;
  arch get_arch() const;
  capabilities get_capabilities() const;

  // thread management
  result get_threads(std::vector<tid>& out_threads) const;
  result suspend_thread(tid thread_id);
  result resume_thread(tid thread_id);
  result single_step(tid thread_id);

  // register access
  result get_registers(tid thread_id, register_context& out_regs) const;
  result set_registers(tid thread_id, const register_context& regs);

  // memory operations
  result read_memory(addr address, size_t size, std::vector<uint8_t>& out_data) const;
  result write_memory(addr address, const std::vector<uint8_t>& data);
  result get_memory_regions(std::vector<memory_region>& out_regions) const;
  result allocate_memory(size_t size, memory_prot prot, addr& out_address);
  result protect_memory(addr address, size_t size, memory_prot prot);

  // event handling
  result wait_for_event(debug_event& out_event, std::optional<std::chrono::milliseconds> timeout = {});

  // breakpoints
  result set_breakpoint(addr address);
  result remove_breakpoint(addr address);

  static std::unique_ptr<session> create_from_impl(std::unique_ptr<session_impl> impl);

private:
  session(std::unique_ptr<session_impl> impl);
  std::unique_ptr<session_impl> pimpl;
};

// utility functions
std::vector<process_info> list_processes();
bool check_debugger_capability();

} // namespace w1::debugger
