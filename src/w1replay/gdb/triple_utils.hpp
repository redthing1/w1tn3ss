#pragma once

#include <string>

#include "w1rewind/format/trace_format.hpp"

namespace w1replay::gdb {

std::string build_process_triple(
    const w1::rewind::arch_descriptor_record& arch, const std::string& os_id, const std::string& abi
);

} // namespace w1replay::gdb
