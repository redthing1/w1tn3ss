#pragma once

#include <string>

#include "w1base/arch_spec.hpp"
#include "w1rewind/format/trace_format.hpp"

namespace w1rewind {

std::string detect_host_os_id();

w1::rewind::arch_descriptor_record build_arch_descriptor(const w1::arch::arch_spec& arch);

w1::rewind::environment_record build_host_environment_record(const w1::rewind::arch_descriptor_record& arch);

} // namespace w1rewind
