#pragma once

#include <sol/sol.hpp>
#include <string>
#include <memory>
#include <redlog.hpp>
#include "script_config.hpp"

namespace w1::tracers::script {

/**
 * handles loading and validation of lua scripts
 * extracted from script_tracer to improve separation of concerns
 */
class script_loader {
private:
    redlog::logger logger_;
    
public:
    script_loader();
    
    struct load_result {
        bool success = false;
        sol::table script_table;
        std::string error_message;
    };
    
    /**
     * load and validate a script file
     * @param lua The lua state to load into
     * @param config The script configuration
     * @return Load result with script table if successful
     */
    load_result load_script(sol::state& lua, const config& cfg);
    
    /**
     * validate that a loaded script has the required structure
     * @param script_table The loaded script table
     * @return True if valid, false otherwise
     */
    bool validate_script(const sol::table& script_table);
    
    /**
     * call the script's init function if it exists
     * @param script_table The loaded script table
     * @return True if successful or no init function, false on error
     */
    bool call_init_function(const sol::table& script_table);
};

} // namespace w1::tracers::script