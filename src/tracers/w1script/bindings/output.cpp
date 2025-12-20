#include "output.hpp"

#include "util.hpp"

#include <redlog.hpp>

#include <chrono>
#include <iomanip>
#include <sstream>

namespace w1::tracers::script::bindings {

namespace {

std::string format_timestamp() {
  auto now = std::chrono::system_clock::now();
  auto time_t = std::chrono::system_clock::to_time_t(now);
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

  std::stringstream ss;
  ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%S");
  ss << '.' << std::setfill('0') << std::setw(3) << ms.count() << 'Z';
  return ss.str();
}

} // namespace

void setup_output_bindings(sol::state& lua, sol::table& w1_module, runtime::script_context& context) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up output bindings");

  sol::table output = lua.create_table();

  output.set_function(
      "open",
      [&lua, &context](const std::string& filename, sol::optional<sol::table> metadata) -> bool {
        sol::table meta_table = metadata ? metadata.value() : lua.create_table();
        meta_table["type"] = "metadata";
        if (!meta_table["version"].valid()) {
          meta_table["version"] = "1.0";
        }
        if (!meta_table["timestamp"].valid()) {
          meta_table["timestamp"] = format_timestamp();
        }
        if (!meta_table["tracer"].valid()) {
          meta_table["tracer"] = "w1script";
        }

        std::string json_metadata = lua_table_to_json(meta_table);
        return context.output().open(filename, json_metadata);
      }
  );

  output.set_function(
      "write",
      [&context](sol::object event_obj) -> bool {
        if (event_obj.is<sol::table>()) {
          std::string json = lua_table_to_json(event_obj.as<sol::table>());
          return context.output().write_event(json);
        }
        if (event_obj.is<std::string>()) {
          return context.output().write_event(event_obj.as<std::string>());
        }
        return false;
      }
  );

  output.set_function("close", [&context]() { context.output().close(); });

  output.set_function("is_open", [&context]() { return context.output().is_open(); });

  output.set_function("count", [&context]() { return context.output().event_count(); });

  w1_module["output"] = output;
}

} // namespace w1::tracers::script::bindings
