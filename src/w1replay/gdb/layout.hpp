#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "w1rewind/format/trace_format.hpp"

namespace w1replay::gdb {

struct register_desc {
  std::string name;
  uint32_t bits = 0;
  std::optional<size_t> trace_index;
  bool is_pc = false;
  bool is_sp = false;
};

struct register_layout {
  std::vector<register_desc> registers;
  int pc_reg_num = -1;
  int sp_reg_num = -1;
  std::string architecture;
  std::string feature_name;
};

register_layout build_register_layout(
    w1::rewind::trace_arch arch,
    uint32_t pointer_size,
    const std::vector<std::string>& trace_registers
);

} // namespace w1replay::gdb
