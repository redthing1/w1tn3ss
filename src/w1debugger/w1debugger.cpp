#include "w1debugger.hpp"
#include "session_impl.hpp"

#ifdef __APPLE__
#include "platform/darwin/darwin_debugger.hpp"
#elif __linux__
#include "platform/linux/linux_debugger.hpp"
#elif _WIN32
#include "platform/windows/windows_debugger.hpp"
#endif

namespace w1::debugger {

session::session(std::unique_ptr<session_impl> impl) : pimpl(std::move(impl)) {}

session::~session() = default;

std::unique_ptr<session> session::create_from_impl(std::unique_ptr<session_impl> impl) {
  return std::unique_ptr<session>(new session(std::move(impl)));
}

std::unique_ptr<session> session::attach(pid target_pid, const config& cfg, result& out_result) {
#ifdef __APPLE__
  return darwin::session_attach(target_pid, cfg, out_result);
#elif __linux__
  return linux::session_attach(target_pid, cfg, out_result);
#elif _WIN32
  return windows::session_attach(target_pid, cfg, out_result);
#else
  out_result = make_error_result(error_code::not_implemented, "platform not supported");
  return nullptr;
#endif
}

std::unique_ptr<session> session::launch(const std::string& path, const config& cfg, result& out_result) {
#ifdef __APPLE__
  return darwin::session_launch(path, cfg, out_result);
#elif __linux__
  return linux::session_launch(path, cfg, out_result);
#elif _WIN32
  return windows::session_launch(path, cfg, out_result);
#else
  out_result = make_error_result(error_code::not_implemented, "platform not supported");
  return nullptr;
#endif
}

// delegate all methods to pimpl
result session::detach() { return pimpl->detach(); }
result session::kill() { return pimpl->kill(); }
result session::continue_execution() { return pimpl->continue_execution(); }
pid session::get_pid() const { return pimpl->get_pid(); }
arch session::get_arch() const { return pimpl->get_arch(); }
capabilities session::get_capabilities() const { return pimpl->get_capabilities(); }

result session::get_threads(std::vector<tid>& out_threads) const { return pimpl->get_threads(out_threads); }

result session::suspend_thread(tid thread_id) { return pimpl->suspend_thread(thread_id); }

result session::resume_thread(tid thread_id) { return pimpl->resume_thread(thread_id); }

result session::single_step(tid thread_id) { return pimpl->single_step(thread_id); }

result session::get_registers(tid thread_id, register_context& out_regs) const {
  return pimpl->get_registers(thread_id, out_regs);
}

result session::set_registers(tid thread_id, const register_context& regs) {
  return pimpl->set_registers(thread_id, regs);
}

result session::read_memory(addr address, size_t size, std::vector<uint8_t>& out_data) const {
  return pimpl->read_memory(address, size, out_data);
}

result session::write_memory(addr address, const std::vector<uint8_t>& data) {
  return pimpl->write_memory(address, data);
}

result session::get_memory_regions(std::vector<memory_region>& out_regions) const {
  return pimpl->get_memory_regions(out_regions);
}

result session::allocate_memory(size_t size, memory_prot prot, addr& out_address) {
  return pimpl->allocate_memory(size, prot, out_address);
}

result session::protect_memory(addr address, size_t size, memory_prot prot) {
  return pimpl->protect_memory(address, size, prot);
}

result session::wait_for_event(debug_event& out_event, std::optional<std::chrono::milliseconds> timeout) {
  return pimpl->wait_for_event(out_event, timeout);
}

result session::set_breakpoint(addr address) { return pimpl->set_breakpoint(address); }

result session::remove_breakpoint(addr address) { return pimpl->remove_breakpoint(address); }

// utility functions
std::vector<process_info> list_processes() {
#ifdef __APPLE__
  return darwin::list_processes();
#elif __linux__
  return linux::list_processes();
#elif _WIN32
  return windows::list_processes();
#else
  return {};
#endif
}

bool check_debugger_capability() {
#ifdef __APPLE__
  return darwin::check_debugger_capability();
#elif __linux__
  return linux::check_debugger_capability();
#elif _WIN32
  return windows::check_debugger_capability();
#else
  return false;
#endif
}

} // namespace w1::debugger