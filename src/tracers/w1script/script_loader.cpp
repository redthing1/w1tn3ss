#include "script_loader.hpp"
#include <fstream>
#include <sstream>

namespace w1::tracers::script {

script_loader::script_loader() : logger_(redlog::get_logger("w1.script_loader")) {}

script_loader::load_result script_loader::load_script(sol::state& lua, const config& cfg) {
    load_result result;
    
    try {
        // expose config to the script
        sol::table config_table = lua.create_table();
        for (const auto& pair : cfg.script_config) {
            config_table[pair.first] = pair.second;
        }
        lua["config"] = config_table;
        
        // load the script file
        logger_.dbg("loading script file", redlog::field("path", cfg.script_path));
        sol::load_result script = lua.load_file(cfg.script_path);
        
        if (!script.valid()) {
            sol::error err = script;
            result.error_message = err.what();
            logger_.err("failed to load script", redlog::field("error", result.error_message));
            return result;
        }
        
        // execute the script
        sol::protected_function_result exec_result = script();
        if (!exec_result.valid()) {
            sol::error err = exec_result;
            result.error_message = err.what();
            logger_.err("failed to execute script", redlog::field("error", result.error_message));
            return result;
        }
        
        // get the returned table
        if (!exec_result.return_count() || exec_result.get_type() != sol::type::table) {
            result.error_message = "script must return a table";
            logger_.err(result.error_message);
            return result;
        }
        
        result.script_table = exec_result;
        
        // validate the script structure
        if (!validate_script(result.script_table)) {
            result.error_message = "script validation failed";
            return result;
        }
        
        // NOTE: init function is NOT called here
        // it should be called after the tracer methods are injected
        
        result.success = true;
        logger_.inf("script loaded successfully", redlog::field("path", cfg.script_path));
        return result;
        
    } catch (const std::exception& e) {
        result.error_message = std::string("exception loading script: ") + e.what();
        logger_.err("exception loading script", redlog::field("error", e.what()));
        return result;
    }
}

bool script_loader::validate_script(const sol::table& script_table) {
    // currently we just check that it's a valid table
    // could add more validation here in the future
    if (!script_table.valid()) {
        logger_.err("invalid script table");
        return false;
    }
    
    // optionally check for required functions/callbacks
    // for now we keep it flexible
    return true;
}

bool script_loader::call_init_function(const sol::table& script_table) {
    sol::optional<sol::function> init_fn = script_table["init"];
    if (init_fn) {
        try {
            logger_.dbg("calling script init function");
            init_fn.value()();
            return true;
        } catch (const sol::error& e) {
            logger_.err("error in script init function", redlog::field("error", e.what()));
            return false;
        }
    }
    
    // no init function is fine
    return true;
}

} // namespace w1::tracers::script