#pragma once

#ifdef WITNESS_SCRIPT_ENABLED

#include <sol/sol.hpp>
#include <QBDI.h>

// Include all binding modules
#include "bindings/core_types.hpp"
#include "bindings/register_access.hpp"
#include "bindings/vm_control.hpp"
#include "bindings/memory_analysis.hpp"
#include "bindings/utilities.hpp"
#include "bindings/callback_system.hpp"

namespace w1::tracers::script {

/**
 * @brief Setup comprehensive QBDI bindings for Lua scripting
 *
 * This function orchestrates the setup of all QBDI-related bindings
 * for the Lua scripting environment. It creates the main 'w1' module
 * and delegates to specialized binding modules for different categories
 * of functionality:
 *
 * - Core types and enums (VMAction, InstAnalysis)
 * - Platform-specific register access functions
 * - VM control and instruction analysis
 * - Memory access and analysis
 * - Utility functions (logging, file I/O, JSON, timestamps)
 * - Callback system for comprehensive QBDI instrumentation
 *
 * The bindings are organized into logical modules to improve maintainability
 * and make it easier to extend with additional QBDI functionality.
 *
 * @param lua The Sol2 Lua state to register all bindings with
 */
void setup_qbdi_bindings(sol::state& lua);

} // namespace w1::tracers::script

#endif // WITNESS_SCRIPT_ENABLED