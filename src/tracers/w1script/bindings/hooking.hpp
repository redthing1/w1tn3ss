/**
 * @file hooking.hpp
 * @brief Hook registration bindings for w1script
 *
 * This module provides hook registration functions for Lua scripts,
 * allowing dynamic instrumentation of arbitrary addresses, modules,
 * and address ranges using QBDI callbacks.
 *
 * @author w1tn3ss Development Team
 * @date 2025
 */

#pragma once

#include <sol/sol.hpp>
#include <QBDI.h>
#include <memory>

namespace w1::hooking {
class hook_manager;
}

namespace w1::tracers::script::bindings {

/**
 * @brief Setup hook registration functions for Lua bindings
 *
 * This module provides hook registration functions:
 * - hook_addr(address, handler) - Hook specific address
 * - hook_module(module, offset, handler) - Hook module+offset
 * - hook_range(start, end, handler) - Hook address range
 * - remove_hook(id) - Remove a specific hook
 * - remove_all_hooks() - Remove all hooks
 *
 * @param lua The Sol2 Lua state to register bindings with
 * @param w1_module The w1 module table to add bindings to
 * @param hook_mgr The hook manager instance to use
 */
void setup_hooking(sol::state& lua, sol::table& w1_module, std::shared_ptr<w1::hooking::hook_manager> hook_mgr);

} // namespace w1::tracers::script::bindings