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
    const w1::rewind::target_info_record& target,
    const std::vector<w1::rewind::register_spec>& register_specs
);

} // namespace w1replay::gdb
