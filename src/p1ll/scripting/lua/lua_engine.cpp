#include "lua_engine.hpp"
#include "lua_bindings.hpp"
#include <redlog.hpp>
#include <fstream>
#include <sstream>

namespace p1ll::scripting::lua {

lua_engine::lua_engine() {
  setup_lua_environment();
  setup_logging_integration();
}

void lua_engine::setup_lua_environment() {
  auto log = redlog::get_logger("p1ll.lua_engine");
  log.dbg("setting up lua environment");

  // open standard lua libraries
  lua_.open_libraries(sol::lib::base, sol::lib::string, sol::lib::math, sol::lib::table, sol::lib::io, sol::lib::os);

  log.dbg("lua environment ready (bindings setup deferred)");
}

void lua_engine::setup_logging_integration() {
  auto log = redlog::get_logger("p1ll.lua_engine");
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

engine::result<engine::apply_report> lua_engine::execute_script(
    engine::session& session, const std::string& script_content
) {
  auto log = redlog::get_logger("p1ll.lua_engine");

  log.inf("executing lua script", redlog::field("mode", session.is_dynamic() ? "dynamic" : "static"));

  try {
    setup_p1ll_bindings(lua_, session);

    auto script_result = lua_.script(script_content);
    if (!script_result.valid()) {
      sol::error error = script_result;
      log.err("lua script failed", redlog::field("error", error.what()));
      return engine::error_result<engine::apply_report>(
          engine::error_code::invalid_argument, "lua script error: " + std::string(error.what())
      );
    }

    return call_cure_function();
  } catch (const sol::error& e) {
    log.err("lua execution error", redlog::field("error", e.what()));
    return engine::error_result<engine::apply_report>(
        engine::error_code::internal_error, "lua execution error: " + std::string(e.what())
    );
  } catch (const std::exception& e) {
    log.err("lua execution c++ exception", redlog::field("error", e.what()));
    return engine::error_result<engine::apply_report>(
        engine::error_code::internal_error, "lua execution failed: " + std::string(e.what())
    );
  }
}

engine::result<engine::apply_report> lua_engine::call_cure_function() {
  auto log = redlog::get_logger("p1ll.lua_engine");

  try {
    sol::function cure_func = lua_["cure"];
    if (!cure_func.valid()) {
      log.err("cure function not found");
      return engine::error_result<engine::apply_report>(
          engine::error_code::invalid_argument, "cure function not found in script"
      );
    }

    log.dbg("calling cure function");
    auto cure_result = cure_func();

    if (!cure_result.valid()) {
      sol::error error = cure_result;
      log.err("cure function failed", redlog::field("error", error.what()));
      return engine::error_result<engine::apply_report>(
          engine::error_code::internal_error, "cure function failed: " + std::string(error.what())
      );
    }

    sol::object result_obj = cure_result;
    if (result_obj.is<apply_report_wrapper>()) {
      auto wrapper = result_obj.as<apply_report_wrapper>();
      engine::apply_report report;
      report.success = wrapper.success;
      report.applied = static_cast<size_t>(wrapper.applied);
      report.failed = static_cast<size_t>(wrapper.failed);
      for (const auto& message : wrapper.error_messages) {
        report.diagnostics.push_back(engine::make_status(engine::error_code::internal_error, message));
      }

      log.inf(
          "cure completed", redlog::field("success", report.success), redlog::field("applied", report.applied),
          redlog::field("failed", report.failed)
      );
      return engine::ok_result(report);
    }

    if (result_obj.is<sol::table>()) {
      sol::table table = result_obj;
      engine::apply_report report;
      report.success = table["success"].get_or(false);
      report.applied = table["applied"].get_or(0);
      report.failed = table["failed"].get_or(0);
      log.inf(
          "cure completed", redlog::field("success", report.success), redlog::field("applied", report.applied),
          redlog::field("failed", report.failed)
      );
      return engine::ok_result(report);
    }

    log.err("cure function returned unexpected type");
    return engine::error_result<engine::apply_report>(
        engine::error_code::invalid_argument, "cure function returned unexpected type"
    );
  } catch (const sol::error& e) {
    log.err("cure function lua error", redlog::field("error", e.what()));
    return engine::error_result<engine::apply_report>(
        engine::error_code::internal_error, "cure function lua error: " + std::string(e.what())
    );
  } catch (const std::exception& e) {
    log.err("cure function c++ exception", redlog::field("error", e.what()));
    return engine::error_result<engine::apply_report>(
        engine::error_code::internal_error, "cure function failed: " + std::string(e.what())
    );
  }
}

} // namespace p1ll::scripting::lua
