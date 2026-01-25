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
  bool is_flags = false;
  bool is_fp = false;
  std::optional<int> dwarf_regnum;
  std::optional<int> ehframe_regnum;
  w1::rewind::register_class reg_class = w1::rewind::register_class::unknown;
  w1::rewind::register_value_kind value_kind = w1::rewind::register_value_kind::unknown;
};

struct register_layout {
  std::vector<register_desc> registers;
  int pc_reg_num = -1;
  int sp_reg_num = -1;
  std::string architecture;
  std::string feature_name;
};

register_layout build_register_layout(
    const w1::arch::arch_spec& arch, const std::vector<w1::rewind::register_spec>& register_specs
);

} // namespace w1replay::gdb
