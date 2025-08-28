#pragma once

#include "../../w1debugger.hpp"

namespace w1::debugger::windows {

std::unique_ptr<session> session_attach(pid target_pid, const config& cfg, result& out_result);
std::unique_ptr<session> session_launch(const std::string& path, const config& cfg, result& out_result);

std::vector<process_info> list_processes();
bool check_debugger_capability();

} // namespace w1::debugger::windows