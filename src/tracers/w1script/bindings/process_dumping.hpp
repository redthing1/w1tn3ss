#pragma once

#include <sol/sol.hpp>

namespace w1::tracers::script::bindings {

/**
 * @brief setup process dumping functionality for lua scripts
 *
 * this module provides lua bindings for dumping process memory and state
 * using the w1dump infrastructure. it exposes a simple api for creating
 * comprehensive process dumps from within lua scripts.
 *
 * exposed functions:
 * - w1.dump_process(vm, gpr, fpr, options) - dump process with options table
 *
 * options table structure:
 * {
 *   output = "filename.w1dump",      -- output file path
 *   dump_memory = false,             -- include memory content
 *   filters = {                      -- filter strings
 *     "all:module_name",
 *     "code:module1,module2",
 *     "data:_anon"
 *   },
 *   max_region_size = 104857600      -- max region size in bytes (100mb default)
 * }
 *
 * @param lua the sol2 lua state
 * @param w1_module the w1 module table to add functions to
 */
void setup_process_dumping(sol::state& lua, sol::table& w1_module);

} // namespace w1::tracers::script::bindings