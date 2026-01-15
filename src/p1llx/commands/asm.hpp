#pragma once

#include <cstdint>
#include <string>

namespace p1llx::commands {

struct asm_request {
  std::string text;
  std::string platform;
  bool has_address = false;
  uint64_t address = 0;
};

int asm_command(const asm_request& request);

} // namespace p1llx::commands
