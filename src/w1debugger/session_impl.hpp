#pragma once

#include "types.hpp"
#include "error.hpp"

namespace w1::debugger {

// platform-specific session implementation base
class session_impl {
public:
  virtual ~session_impl() = default;

  virtual result detach() = 0;
  virtual result kill() = 0;
  virtual result continue_execution() = 0;
  virtual pid get_pid() const = 0;
  virtual arch get_arch() const = 0;
  virtual capabilities get_capabilities() const = 0;
  virtual result get_threads(std::vector<tid>& out_threads) const = 0;
  virtual result suspend_thread(tid thread_id) = 0;
  virtual result resume_thread(tid thread_id) = 0;
  virtual result single_step(tid thread_id) = 0;
  virtual result get_registers(tid thread_id, register_context& out_regs) const = 0;
  virtual result set_registers(tid thread_id, const register_context& regs) = 0;
  virtual result read_memory(addr address, size_t size, std::vector<uint8_t>& out_data) const = 0;
  virtual result write_memory(addr address, const std::vector<uint8_t>& data) = 0;
  virtual result get_memory_regions(std::vector<memory_region>& out_regions) const = 0;
  virtual result allocate_memory(size_t size, memory_prot prot, addr& out_address) = 0;
  virtual result protect_memory(addr address, size_t size, memory_prot prot) = 0;
  virtual result wait_for_event(debug_event& out_event, std::optional<std::chrono::milliseconds> timeout) = 0;
  virtual result set_breakpoint(addr address) = 0;
  virtual result remove_breakpoint(addr address) = 0;
};

} // namespace w1::debugger
