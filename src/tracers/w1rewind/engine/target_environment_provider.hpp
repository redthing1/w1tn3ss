#pragma once

#include <string>
#include <vector>

#include "w1base/arch_spec.hpp"
#include "w1rewind/format/trace_format.hpp"

namespace w1rewind {

std::string detect_os_id();

w1::rewind::target_environment_record build_target_environment(
    const std::vector<w1::rewind::memory_region_record>& memory_map,
    const std::vector<w1::rewind::module_record>& modules, const w1::arch::arch_spec& arch
);

} // namespace w1rewind
