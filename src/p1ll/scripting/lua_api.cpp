#include "lua_api.hpp"
#include "lua_bindings.hpp"
#include "p1ll.hpp"
#include <redlog.hpp>
#include <fstream>
#include <sstream>

namespace p1ll::scripting {

lua_api::lua_api() {
  setup_lua_environment();
  setup_logging_integration();
}

void lua_api::setup_lua_environment() {
  auto log = redlog::get_logger("p1ll.lua_api");
  log.dbg("setting up lua environment");

  // open standard lua libraries
  lua_.open_libraries(sol::lib::base, sol::lib::string, sol::lib::math, sol::lib::table, sol::lib::io, sol::lib::os);

  log.dbg("lua environment ready (bindings setup deferred)");
}

void lua_api::setup_logging_integration() {
  auto log = redlog::get_logger("p1ll.lua_api");
  log.dbg("setting up logging integration");

  // override lua print function to use redlog
  lua_["print"] = [](sol::variadic_args args) {
    auto log = redlog::get_logger("p1ll.lua.print");
    std::ostringstream oss;

    for (const auto& arg : args) {
      if (oss.tellp() > 0) {
        oss << "\t";
      }
      oss << lua_tostring(args.lua_state(), arg.stack_index());
    }

    log.inf(oss.str());
  };

  log.dbg("logging integration complete");
}

cure_result lua_api::execute_script_content_with_buffer(
    const context& ctx, const std::string& script_content, std::vector<uint8_t>& buffer_data
) {
  auto log = redlog::get_logger("p1ll.lua_api");

  cure_result result;

  log.inf("executing cure script with buffer", redlog::field("buffer_size", buffer_data.size()));

  try {
    // setup p1ll bindings with context and buffer
    setup_p1ll_bindings_with_buffer(lua_, ctx, buffer_data);

    // load and execute script content
    auto script_result = lua_.script(script_content);

    if (!script_result.valid()) {
      sol::error error = script_result;
      result.add_error("lua script error: " + std::string(error.what()));
      log.err("lua script failed", redlog::field("error", error.what()));
      return result;
    }

    // call cure function
    return call_cure_function();

  } catch (const std::exception& e) {
    result.add_error("script execution failed: " + std::string(e.what()));
    log.err("script execution exception", redlog::field("error", e.what()));
    return result;
  }
}

cure_result lua_api::execute_script(const context& ctx, const std::string& script_content) {
  auto log = redlog::get_logger("p1ll.lua_api");

  cure_result result;

  log.inf("executing cure script from string");

  try {
    // setup p1ll bindings with context
    setup_p1ll_bindings(lua_, ctx);

    // load and execute script content
    auto script_result = lua_.script(script_content);

    if (!script_result.valid()) {
      sol::error error = script_result;
      result.add_error("lua script error: " + std::string(error.what()));
      log.err("lua script failed", redlog::field("error", error.what()));
      return result;
    }

    // call cure function
    return call_cure_function();

  } catch (const std::exception& e) {
    result.add_error("script execution failed: " + std::string(e.what()));
    log.err("script execution exception", redlog::field("error", e.what()));
    return result;
  }
}

cure_result lua_api::call_cure_function() {
  auto log = redlog::get_logger("p1ll.lua_api");

  cure_result result;

  try {
    // check if cure function exists
    sol::function cure_func = lua_["cure"];
    if (!cure_func.valid()) {
      result.add_error("cure function not found in script");
      log.err("cure function not found");
      return result;
    }

    log.dbg("calling cure function");

    // call cure function
    auto cure_result = cure_func();

    if (!cure_result.valid()) {
      sol::error error = cure_result;
      result.add_error("cure function failed: " + std::string(error.what()));
      log.err("cure function failed", redlog::field("error", error.what()));
      return result;
    }

    // extract result
    if (cure_result.get_type() == sol::type::userdata) {
      auto extracted_result = cure_result.get<p1ll::cure_result>();
      log.inf(
          "cure function completed", redlog::field("success", extracted_result.success),
          redlog::field("applied", extracted_result.patches_applied),
          redlog::field("failed", extracted_result.patches_failed)
      );
      return extracted_result;
    } else {
      result.add_error("cure function returned unexpected type");
      return result;
    }

  } catch (const std::exception& e) {
    result.add_error("cure function call failed: " + std::string(e.what()));
    log.err("cure function exception", redlog::field("error", e.what()));
    return result;
  }
}

} // namespace p1ll::scripting