/**
 * @file memory_analysis.hpp
 * @brief Memory access and analysis bindings for w1script
 *
 * This module provides comprehensive memory analysis capabilities including safe
 * memory read/write operations, memory mapping inspection, address validation,
 * and advanced memory management functions for dynamic analysis.
 *
 * @author w1tn3ss Development Team
 * @date 2025
 */

#pragma once

#ifdef WITNESS_SCRIPT_ENABLED

#include <sol/sol.hpp>
#include <QBDI.h>

namespace w1::tracers::script::bindings {

/**
 * @brief Setup memory access and analysis functions for Lua bindings
 *
 * This module provides functions for analyzing memory accesses performed
 * by the currently executing instruction, including:
 * - Memory access retrieval and analysis
 * - Memory value formatting utilities
 * - Memory read operations (when safe)
 *
 * The memory access functions return detailed information about each memory
 * operation (read/write) performed by the current instruction, including
 * addresses, values, sizes, and types.
 *
 * @param lua The Sol2 Lua state to register bindings with
 * @param w1_module The w1 module table to add bindings to
 */
void setup_memory_analysis(sol::state& lua, sol::table& w1_module);

} // namespace w1::tracers::script::bindings

#endif // WITNESS_SCRIPT_ENABLED