#include "windows_debugger.hpp"
#include "../../error.hpp"

namespace w1::debugger::windows {

std::unique_ptr<session> session_attach(pid target_pid, const config& cfg, result& out_result) {
  out_result = make_error_result(error_code::not_implemented, "windows debugger not yet implemented");
  return nullptr;
}

std::unique_ptr<session> session_launch(const std::string& path, const config& cfg, result& out_result) {
  out_result = make_error_result(error_code::not_implemented, "windows debugger not yet implemented");
  return nullptr;
}

std::vector<process_info> list_processes() {
  return {};
}

bool check_debugger_capability() {
  return false;
}

} // namespace w1::debugger::windows