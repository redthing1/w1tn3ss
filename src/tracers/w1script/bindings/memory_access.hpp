/**
 * @file memory_access.hpp
 * @brief Safe memory read/write bindings for w1script
 *
 * This module provides safe memory access functions using the
 * safe_memory.hpp infrastructure to prevent segfaults and crashes.
 *
 * @author w1tn3ss Development Team
 * @date 2025
 */

#pragma once

#include <sol/sol.hpp>
#include <QBDI.h>

namespace w1::tracers::script::bindings {

/**
 * @brief Setup safe memory access functions for Lua bindings
 *
 * This module provides functions for safe memory access:
 * - read_mem(vm, address, size) - Read memory safely
 * - write_mem(vm, address, data) - Write memory safely
 * - read_string(vm, address, max_length) - Read null-terminated string
 * - read_wstring(vm, address, max_length) - Read wide string
 *
 * All functions use safe_memory.hpp to validate memory access
 * before performing operations.
 *
 * @param lua The Sol2 Lua state to register bindings with
 * @param w1_module The w1 module table to add bindings to
 */
void setup_memory_access(sol::state& lua, sol::table& w1_module);

} // namespace w1::tracers::script::bindings