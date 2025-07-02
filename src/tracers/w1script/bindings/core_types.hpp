/**
 * @file core_types.hpp
 * @brief Core QBDI types and enums bindings for w1script
 *
 * This module exposes essential QBDI types, enums, and structures to Lua scripts,
 * providing the foundation for dynamic binary analysis. Includes VMAction enums,
 * memory access types, analysis types, and core QBDI structures.
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
 * @brief Setup core QBDI types and enums for Lua bindings
 *
 * This module contains the fundamental QBDI types and enumerations
 * that are exposed to the Lua scripting environment, including:
 * - VMAction enum for controlling VM execution flow
 * - InstAnalysis usertype for instruction analysis data
 *
 * @param lua The Sol2 Lua state to register bindings with
 * @param w1_module The w1 module table to add bindings to
 */
void setup_core_types(sol::state& lua, sol::table& w1_module);

} // namespace w1::tracers::script::bindings

#endif // WITNESS_SCRIPT_ENABLED