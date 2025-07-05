#pragma once

#include <sol/sol.hpp>
#include <QBDI.h>

// include all binding modules
#include "bindings/core_types.hpp"
#include "bindings/register_access.hpp"
#include "bindings/vm_control.hpp"
#include "bindings/memory_analysis.hpp"
#include "bindings/utilities.hpp"
#include "bindings/callback_system.hpp"

namespace w1::tracers::script {

/**
 * @brief setup comprehensive QBDI bindings for Lua scripting
 *
 * this function orchestrates the setup of all QBDI-related bindings
 * for the Lua scripting environment. it creates the main 'w1' module
 * and delegates to specialized binding modules for different categories
 * of functionality:
 *
 * - core types and enums (VMAction, InstAnalysis)
 * - platform-specific register access functions
 * - VM control and instruction analysis
 * - memory access and analysis
 * - utility functions (logging, file I/O, JSON, timestamps)
 * - callback system for comprehensive QBDI instrumentation
 *
 * the bindings are organized into logical modules to improve maintainability
 * and make it easier to extend with additional QBDI functionality.
 *
 * @param lua the Sol2 Lua state to register all bindings with
 */
void setup_qbdi_bindings(sol::state& lua);

} // namespace w1::tracers::script
