#pragma once

#include <string>

#include "w1base/arch_spec.hpp"

namespace w1replay::gdb {

std::string build_process_triple(
    const w1::arch::arch_spec& spec, const std::string& os_id, const std::string& abi
);

} // namespace w1replay::gdb
