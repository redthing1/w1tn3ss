#pragma once

#include <string>

namespace p1llx::commands {

struct sig_request {
  std::string pattern;
  std::string input_file;
  bool single = false;
};

int sig_command(const sig_request& request);

} // namespace p1llx::commands
