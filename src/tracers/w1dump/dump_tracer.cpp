#include "dump_tracer.hpp"

#include <algorithm>
#include <sstream>
#include <utility>

namespace w1dump {

dump_tracer::dump_tracer(dump_config config) : config_(std::move(config)) {
  log_.inf(
      "dump tracer created", redlog::field("output", config_.output),
      redlog::field("dump_memory", config_.dump_memory_content), redlog::field("filter_count", config_.filters.size())
  );
}

QBDI::VMAction dump_tracer::on_vm_start(
    w1::trace_context& ctx, const w1::sequence_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  (void) event;
  (void) state;

  if (config_.dump_on_entry && !dumped_) {
    perform_dump(ctx, vm, gpr, fpr);
    return QBDI::VMAction::STOP;
  }

  return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction dump_tracer::on_instruction_pre(
    w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  (void) event;

  if (!config_.dump_on_entry && !dumped_) {
    perform_dump(ctx, vm, gpr, fpr);
    return QBDI::VMAction::STOP;
  }

  return QBDI::VMAction::CONTINUE;
}

void dump_tracer::perform_dump(
    w1::trace_context& ctx, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  if (dumped_) {
    return;
  }

  QBDI::VM* qbdi_vm = static_cast<QBDI::VM*>(vm);
  if (!qbdi_vm) {
    log_.err("vm instance is null");
    return;
  }

  QBDI::GPRState local_gpr{};
  QBDI::FPRState local_fpr{};
  const QBDI::GPRState* gpr_ptr = gpr;
  const QBDI::FPRState* fpr_ptr = fpr;

  if (!gpr_ptr) {
    local_gpr = *qbdi_vm->getGPRState();
    gpr_ptr = &local_gpr;
  }
  if (!fpr_ptr) {
    local_fpr = *qbdi_vm->getFPRState();
    fpr_ptr = &local_fpr;
  }

  w1::dump::dump_options options;
  options.dump_memory_content = config_.dump_memory_content;
  options.filters = parse_filters();
  options.max_region_size = config_.max_region_size;

  try {
    auto dump = w1::dump::process_dumper::dump_current(
        vm, ctx.memory(), ctx.thread_id(), *gpr_ptr, *fpr_ptr, options
    );
    w1::dump::process_dumper::save_dump(dump, config_.output);

    log_.inf(
        "dump completed", redlog::field("file", config_.output), redlog::field("modules", dump.modules.size()),
        redlog::field("regions", dump.regions.size())
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

    size_t colon_pos = filter_str.find(':');
    std::string type_str = filter_str.substr(0, colon_pos);

    if (type_str == "all") {
      filter.type = w1::dump::dump_options::filter::region_type::all;
    } else if (type_str == "code") {
      filter.type = w1::dump::dump_options::filter::region_type::code;
    } else if (type_str == "data") {
      filter.type = w1::dump::dump_options::filter::region_type::data;
    } else if (type_str == "stack") {
      filter.type = w1::dump::dump_options::filter::region_type::stack;
    } else {
      log_.err("invalid filter type", redlog::field("type", type_str));
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

    result.push_back(std::move(filter));
  }

  return result;
}

} // namespace w1dump
