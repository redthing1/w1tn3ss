#pragma once

#include <cstdint>
#include <string>

namespace p1llx::commands {

struct disasm_request {
  std::string bytes;
  std::string arch;
  bool has_address = false;
  uint64_t address = 0;
};

int disasm_command(const disasm_request& request);

} // namespace p1llx::commands
