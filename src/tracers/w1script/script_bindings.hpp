#pragma once

#include <sol/sol.hpp>
#include <QBDI.h>
#include <memory>

// include all binding modules
#include "bindings/core_types.hpp"
#include "bindings/register_access.hpp"
#include "bindings/vm_control.hpp"
#include "bindings/vm_core.hpp"
#include "bindings/memory_access.hpp"
#include "bindings/memory_analysis.hpp"
#include "bindings/module_analysis.hpp"
#include "bindings/utilities.hpp"
#include "bindings/callback_system.hpp"
#include "bindings/api_analysis.hpp"
#include "bindings/hooking.hpp"
#include "bindings/signature_scanning.hpp"
#include "bindings/calling_convention.hpp"
#include "bindings/symbol_resolution.hpp"
#include "bindings/gadget_execution.hpp"

namespace w1::hooking {
class hook_manager;
}

namespace w1tn3ss::gadget {
class gadget_executor;
}

namespace w1::tracers::script {

/**
 * @brief setup comprehensive qbdi bindings for lua scripting
 *
 * this function orchestrates the setup of all qbdi-related bindings
 * for the lua scripting environment. it creates the main 'w1' module
 * and delegates to specialized binding modules for different categories
 * of functionality:
 *
 * - core types and enums (vmaction, instanalysis)
 * - platform-specific register access functions
 * - VM control and instruction analysis
 * - memory access and analysis
 * - utility functions (logging, file i/o, json, timestamps)
 * - callback system for comprehensive qbdi instrumentation
 * - api analysis for semantic API monitoring
 *
 * the bindings are organized into logical modules to improve maintainability
 * and make it easier to extend with additional qbdi functionality.
 *
 * @param lua the sol2 lua state to register all bindings with
 * @param tracer_table the tracer instance table (for api callbacks)
 * @param api_manager the api analysis manager (optional)
 */
void setup_qbdi_bindings(
    sol::state& lua, sol::table& tracer_table, std::shared_ptr<bindings::api_analysis_manager>& api_manager,
    std::shared_ptr<w1::hooking::hook_manager>& hook_manager,
    std::shared_ptr<w1tn3ss::gadget::gadget_executor>& gadget_executor
);

} // namespace w1::tracers::script
