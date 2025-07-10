#pragma once

#include <sol/sol.hpp>

namespace w1::tracers::script::bindings {

/**
 * @brief setup symbol resolution functions in lua environment
 * @details provides api for symbol lookup by address or name, pattern matching,
 *          and module symbol enumeration
 *
 * exposed functions:
 * - symbol_resolve_address(address) -> table with symbol info or nil
 * - symbol_resolve_name(name, module_hint) -> address or nil
 * - symbol_find_pattern(pattern, module_hint) -> array of symbol info tables
 * - symbol_get_module_symbols(module_path) -> array of symbol info tables
 * - symbol_get_backend() -> string describing active backend
 * - symbol_clear_cache() -> clears symbol resolution cache
 */
void setup_symbol_resolution(sol::state& lua, sol::table& w1_module);

} // namespace w1::tracers::script::bindings