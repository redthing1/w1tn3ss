#pragma once

#include <sol/sol.hpp>
#include "../core/types.hpp"

namespace p1ll::scripting {

/**
 * @brief Setup comprehensive p1ll bindings for Lua scripting
 *
 * This function orchestrates the setup of all p1ll-related bindings
 * for the Lua scripting environment. It creates the main 'p1' module
 * and provides the beautiful declarative auto-cure API.
 *
 * Key features:
 * - Signature creation and compilation
 * - Patch declarations with module filtering
 * - Auto-cure orchestration
 * - Manual patching API for complex cases
 * - Utility functions (str2hex, hex2str, format_address)
 *
 * @param lua The Sol2 Lua state to register all bindings with
 */
void setup_p1ll_bindings(sol::state& lua);

namespace bindings {

/**
 * @brief Setup core p1ll types and enums
 * @param lua The Sol2 Lua state to register bindings with
 * @param p1_module The p1 module table to add bindings to
 */
void setup_core_types(sol::state& lua, sol::table& p1_module);

/**
 * @brief Setup signature API functions
 * @param lua The Sol2 Lua state to register bindings with
 * @param p1_module The p1 module table to add bindings to
 */
void setup_signature_api(sol::state& lua, sol::table& p1_module);

/**
 * @brief Setup patch API functions
 * @param lua The Sol2 Lua state to register bindings with
 * @param p1_module The p1 module table to add bindings to
 */
void setup_patch_api(sol::state& lua, sol::table& p1_module);

/**
 * @brief Setup auto-cure API functions
 * @param lua The Sol2 Lua state to register bindings with
 * @param p1_module The p1 module table to add bindings to
 */
void setup_auto_cure_api(sol::state& lua, sol::table& p1_module);

/**
 * @brief Setup manual patching API for complex cases
 * @param lua The Sol2 Lua state to register bindings with
 * @param p1_module The p1 module table to add bindings to
 */
void setup_manual_api(sol::state& lua, sol::table& p1_module);

/**
 * @brief Setup utility functions
 * @param lua The Sol2 Lua state to register bindings with
 * @param p1_module The p1 module table to add bindings to
 */
void setup_utilities(sol::state& lua, sol::table& p1_module);

} // namespace bindings

} // namespace p1ll::scripting
