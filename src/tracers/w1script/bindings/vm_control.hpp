/**
 * @file vm_control.hpp
 * @brief VM control and instruction analysis bindings for w1script
 *
 * This module exposes QBDI VM control methods and instruction analysis capabilities
 * to Lua scripts. Includes execution control, instrumentation management, state
 * inspection, and advanced instruction analysis functions.
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
 * @brief Setup VM control and instruction analysis functions for Lua bindings
 *
 * This module provides functions for controlling and analyzing the QBDI VM state,
 * including:
 * - Instruction disassembly retrieval
 * - Address formatting utilities
 * - VM state inspection functions
 *
 * These functions allow Lua scripts to examine the current instruction being
 * executed and make decisions about VM control flow.
 *
 * @param lua The Sol2 Lua state to register bindings with
 * @param w1_module The w1 module table to add bindings to
 */
void setup_vm_control(sol::state& lua, sol::table& w1_module);

} // namespace w1::tracers::script::bindings

#endif // WITNESS_SCRIPT_ENABLED