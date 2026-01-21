#pragma once

#include <vector>

#include "w1base/arch_spec.hpp"
#include "w1rewind/format/trace_format.hpp"
#include "w1runtime/module_registry.hpp"

namespace w1rewind {

std::vector<w1::rewind::module_record> build_module_table(
    const w1::runtime::module_registry& modules, const w1::arch::arch_spec& arch
);

std::vector<w1::rewind::memory_region_record> collect_memory_map(const std::vector<w1::rewind::module_record>& modules);

} // namespace w1rewind
