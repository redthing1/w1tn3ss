/**
 * @file register_access.hpp
 * @brief CPU register access bindings for w1script
 *
 * This module provides comprehensive CPU register access functions for all supported
 * architectures (x86_64, ARM64, ARM32, x86). Includes both getter and setter functions
 * for all general-purpose registers plus helper accessors for the x87 floating-point
 * state on x86/x64 platforms.
 *
 * @author w1tn3ss Development Team
 * @date 2025
 */

#pragma once

#include <sol/sol.hpp>
#include <QBDI.h>

namespace w1::tracers::script::bindings {

/**
 * @brief Setup platform-specific register access functions for Lua bindings
 *
 * This module provides architecture-specific register access functions
 * that allow Lua scripts to read CPU register values from the GPR state.
 * The functions are conditionally compiled based on the target architecture:
 *
 * - x86_64: RAX, RBX, RCX, RDX, RSP, RBP, RSI, RDI, RIP
 * - ARM64: X0, X1, SP, LR, PC (and additional X registers)
 * - ARM32: R0, R1, SP, LR, PC (and additional R registers)
 *
 * All functions take a void* pointer to GPRState (passed as lightuserdata)
 * and return the register value as QBDI::rword.
 *
 * @param lua The Sol2 Lua state to register bindings with
 * @param w1_module The w1 module table to add bindings to
 */
void setup_register_access(sol::state& lua, sol::table& w1_module);

} // namespace w1::tracers::script::bindings
