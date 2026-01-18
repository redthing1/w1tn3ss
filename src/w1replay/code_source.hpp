#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "w1rewind/replay/replay_context.hpp"

namespace w1replay {

class code_source {
public:
  virtual ~code_source() = default;

  virtual bool read_by_address(
      const w1::rewind::replay_context& context,
      uint64_t address,
      std::span<std::byte> out,
      std::string& error
  ) = 0;
};

} // namespace w1replay
