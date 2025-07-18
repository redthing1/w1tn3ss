#include "dump_tracer.hpp"
#include <w1tn3ss/dump/process_dumper.hpp>
#include <w1tn3ss/engine/tracer_engine.hpp>
#include <sstream>
#include <algorithm>

namespace w1dump {

dump_tracer::dump_tracer(const dump_config& config) : config_(config) {
  log_.inf(
      "dump tracer created", redlog::field("output", config_.output),
      redlog::field("dump_memory", config_.dump_memory_content), redlog::field("filter_count", config_.filters.size())
  );
}

void dump_tracer::on_vm_start(QBDI::VMInstanceRef vm) {
  log_.dbg("vm started, checking if dump required");

  if (config_.dump_on_entry && !dumped_) {
    perform_dump(vm);
  }
}

void dump_tracer::perform_dump(QBDI::VMInstanceRef vm) {
  log_.inf("performing process dump");

  // get current state
  QBDI::GPRState gpr;
  QBDI::FPRState fpr;

  QBDI::VM* qbdi_vm = static_cast<QBDI::VM*>(vm);

  gpr = *qbdi_vm->getGPRState();
  fpr = *qbdi_vm->getFPRState();

  // prepare dump options
  w1::dump::dump_options options;
  options.dump_memory_content = config_.dump_memory_content;
  options.filters = parse_filters();
  options.max_region_size = config_.max_region_size;

  try {
    // perform the dump
    auto dump = w1::dump::process_dumper::dump_current(vm, gpr, fpr, options);

    // save to file
    w1::dump::process_dumper::save_dump(dump, config_.output);

    log_.inf(
        "dump completed successfully", redlog::field("file", config_.output),
        redlog::field("modules", dump.modules.size()), redlog::field("regions", dump.regions.size())
    );

    dumped_ = true;

  } catch (const std::exception& e) {
    log_.err("dump failed", redlog::field("error", e.what()));
  }
}

std::vector<w1::dump::dump_options::filter> dump_tracer::parse_filters() const {
  std::vector<w1::dump::dump_options::filter> result;

  for (const auto& filter_str : config_.filters) {
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
      log_.err("invalid filter type", redlog::field("type", type_str));
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

} // namespace w1dump