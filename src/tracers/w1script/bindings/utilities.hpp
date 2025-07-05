#pragma once

#include <sol/sol.hpp>
#include <string>

namespace w1::tracers::script::bindings {

/**
 * @brief Setup utility functions for Lua bindings
 *
 * This module provides essential utility functions for Lua scripts, including:
 * - Logging functions (info, debug, error) integrated with the redlog system
 * - File I/O operations (write, append) for output generation
 * - JSON serialization for converting Lua tables to JSON strings
 * - Timestamp generation for logging and data collection
 *
 * These utilities enable Lua scripts to perform common operations like
 * logging messages, saving data to files, and generating structured output.
 *
 * @param lua The Sol2 Lua state to register bindings with
 * @param w1_module The w1 module table to add bindings to
 */
void setup_utilities(sol::state& lua, sol::table& w1_module);

// helper functions for JSON serialization
// these are exposed in the header for potential reuse by other modules

/**
 * @brief Convert a Lua table to JSON string
 * @param lua_table The Lua table to convert
 * @return JSON string representation
 */
std::string lua_table_to_json(const sol::table& lua_table);

/**
 * @brief Escape a string for JSON format
 * @param str The string to escape
 * @return JSON-escaped string with quotes
 */
std::string escape_json_string(const std::string& str);

/**
 * @brief Check if a Lua table should be serialized as JSON array
 * @param table The table to check
 * @return true if table has consecutive integer keys starting from 1
 */
bool is_lua_array(const sol::table& table);

} // namespace w1::tracers::script::bindings