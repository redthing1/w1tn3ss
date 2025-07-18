#include "process_dumping.hpp"
#include <w1tn3ss/dump/process_dumper.hpp>
#include <w1tn3ss/dump/dump_format.hpp>
#include <redlog.hpp>
#include <sstream>

namespace w1::tracers::script::bindings {

namespace {

// parse filter strings in format "type[:module1,module2,...]"
std::vector<w1::dump::dump_options::filter> parse_filters(const sol::table& filter_table) {
  auto logger = redlog::get_logger("w1.script_dumping");
  std::vector<w1::dump::dump_options::filter> result;

  for (auto& [key, value] : filter_table) {
    if (value.get_type() != sol::type::string) {
      logger.wrn("skipping non-string filter entry");
      continue;
    }

    std::string filter_str = value.as<std::string>();
    w1::dump::dump_options::filter filter;

    // parse format: type[:module1,module2,...]
    size_t colon_pos = filter_str.find(':');
    std::string type_str = filter_str.substr(0, colon_pos);

    // parse type
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

    // parse modules if present
    if (colon_pos != std::string::npos) {
      std::string modules_str = filter_str.substr(colon_pos + 1);
      std::stringstream ss(modules_str);
      std::string module;

      while (std::getline(ss, module, ',')) {
        // trim whitespace
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

} // anonymous namespace

void setup_process_dumping(sol::state& lua, sol::table& w1_module) {
  auto logger = redlog::get_logger("w1.script_dumping");
  logger.dbg("setting up process dumping functions");

  // main dump function
  w1_module.set_function(
      "dump_process",
      [&lua](
          QBDI::VM* vm, const QBDI::GPRState& gpr, const QBDI::FPRState& fpr, sol::optional<sol::table> options_table
      ) -> bool {
        auto logger = redlog::get_logger("w1.script_dumping");

        // prepare dump options with defaults
        w1::dump::dump_options options;
        std::string output_path = "process.w1dump";

        // parse options if provided
        if (options_table) {
          auto& opts = *options_table;

          // output file
          if (opts["output"]) {
            output_path = opts["output"].get<std::string>();
          }

          // dump memory content
          if (opts["dump_memory"]) {
            options.dump_memory_content = opts["dump_memory"].get<bool>();
          }

          // filters
          if (opts["filters"]) {
            sol::table filter_table = opts["filters"];
            options.filters = parse_filters(filter_table);
          }

          // max region size
          if (opts["max_region_size"]) {
            options.max_region_size = opts["max_region_size"].get<uint64_t>();
          }
        }

        try {
          logger.inf(
              "performing process dump from lua", redlog::field("output", output_path),
              redlog::field("dump_memory", options.dump_memory_content),
              redlog::field("filter_count", options.filters.size())
          );

          // perform the dump
          auto dump = w1::dump::process_dumper::dump_current(vm, gpr, fpr, options);

          // save to file
          w1::dump::process_dumper::save_dump(dump, output_path);

          logger.inf(
              "dump completed successfully", redlog::field("file", output_path),
              redlog::field("modules", dump.modules.size()), redlog::field("regions", dump.regions.size())
          );

          return true;

        } catch (const std::exception& e) {
          logger.err("dump failed", redlog::field("error", e.what()));
          return false;
        }
      }
  );

  // helper to create default options table
  w1_module.set_function("dump_default_options", [&lua]() -> sol::table {
    sol::state_view lua_view = lua.lua_state();
    sol::table options = lua_view.create_table();

    options["output"] = "process.w1dump";
    options["dump_memory"] = false;
    options["filters"] = lua_view.create_table();
    options["max_region_size"] = 100 * 1024 * 1024; // 100mb

    return options;
  });

  logger.dbg("process dumping functions registered");
}

} // namespace w1::tracers::script::bindings