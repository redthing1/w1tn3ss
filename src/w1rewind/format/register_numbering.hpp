#pragma once

#include <optional>
#include <string_view>

#include "w1base/arch_spec.hpp"
#include "w1rewind/format/trace_format.hpp"

namespace w1::rewind {

struct register_numbering {
  uint32_t dwarf_regnum = k_register_regnum_unknown;
  uint32_t ehframe_regnum = k_register_regnum_unknown;
};

std::optional<register_numbering> lookup_register_numbering(
    const w1::arch::arch_spec& arch, std::string_view name
);

} // namespace w1::rewind
