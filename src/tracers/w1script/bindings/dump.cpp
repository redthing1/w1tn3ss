#include "dump.hpp"

#include <w1tn3ss/dump/process_dumper.hpp>
#include <w1tn3ss/dump/dump_format.hpp>
#include <redlog.hpp>

#include <sstream>

namespace w1::tracers::script::bindings {

namespace {

std::vector<w1::dump::dump_options::filter> parse_filters(const sol::table& filter_table) {
  auto logger = redlog::get_logger("w1.script_dump");
  std::vector<w1::dump::dump_options::filter> result;

  for (auto& [key, value] : filter_table) {
    if (value.get_type() != sol::type::string) {
      logger.wrn("skipping non-string filter entry");
      continue;
    }

    std::string filter_str = value.as<std::string>();
    w1::dump::dump_options::filter filter;

    size_t colon_pos = filter_str.find(':');
    std::string type_str = filter_str.substr(0, colon_pos);

    if (type_str == "all") {
      filter.region_type = w1::dump::dump_options::filter::ALL;
    } else if (type_str == "code") {
      filter.region_type = w1::dump::dump_options::filter::CODE;
    } else if (type_str == "data") {
      filter.region_type = w1::dump::dump_options::filter::DATA;
    } else if (type_str == "stack") {
      filter.region_type = w1::dump::dump_options::filter::STACK;
    } else {
      logger.err("invalid filter type", redlog::field("type", type_str));
      continue;
    }

    if (colon_pos != std::string::npos) {
      std::string modules_str = filter_str.substr(colon_pos + 1);
      std::stringstream ss(modules_str);
      std::string module;

      while (std::getline(ss, module, ',')) {
        module.erase(0, module.find_first_not_of(" \t"));
        module.erase(module.find_last_not_of(" \t") + 1);
        if (!module.empty()) {
          filter.modules.insert(module);
        }
      }
    }

    result.push_back(filter);
  }

  return result;
}

} // namespace

void setup_dump_bindings(sol::state& lua, sol::table& w1_module) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up dump bindings");

  sol::table dump = lua.create_table();

  dump.set_function(
      "process",
      [](QBDI::VM* vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, sol::optional<sol::table> options_table) -> bool {
        auto logger = redlog::get_logger("w1.script_dump");
        if (!vm || !gpr || !fpr) {
          logger.err("dump requires vm, gpr, and fpr");
          return false;
        }

        w1::dump::dump_options options;
        std::string output_path = "process.w1dump";

        if (options_table) {
          auto& opts = *options_table;
          if (opts["output"].valid()) {
            output_path = opts["output"].get<std::string>();
          }
          if (opts["dump_memory"].valid()) {
            options.dump_memory_content = opts["dump_memory"].get<bool>();
          }
          if (opts["filters"].valid()) {
            options.filters = parse_filters(opts["filters"]);
          }
          if (opts["max_region_size"].valid()) {
            options.max_region_size = opts["max_region_size"].get<uint64_t>();
          }
        }

        try {
          logger.inf("performing process dump", redlog::field("output", output_path));
          auto dump_data = w1::dump::process_dumper::dump_current(vm, *gpr, *fpr, options);
          w1::dump::process_dumper::save_dump(dump_data, output_path);
          logger.inf(
              "dump completed", redlog::field("file", output_path), redlog::field("modules", dump_data.modules.size()),
              redlog::field("regions", dump_data.regions.size())
          );
          return true;
        } catch (const std::exception& e) {
          logger.err("dump failed", redlog::field("error", e.what()));
          return false;
        }
      }
  );

  dump.set_function("default_options", [&lua]() -> sol::table {
    sol::state_view lua_view = lua.lua_state();
    sol::table options = lua_view.create_table();
    options["output"] = "process.w1dump";
    options["dump_memory"] = false;
    options["filters"] = lua_view.create_table();
    options["max_region_size"] = 100 * 1024 * 1024;
    return options;
  });

  w1_module["dump"] = dump;
}

} // namespace w1::tracers::script::bindings
