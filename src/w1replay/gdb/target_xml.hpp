#pragma once

#include <string>

#include "layout.hpp"

namespace w1replay::gdb {

std::string build_target_xml(const register_layout& layout);

} // namespace w1replay::gdb
