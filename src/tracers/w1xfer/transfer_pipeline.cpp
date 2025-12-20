#include "transfer_pipeline.hpp"

#include <chrono>
#include <utility>

#include <w1tn3ss/abi/api_knowledge_db.hpp>
#include <w1tn3ss/runtime/threading/thread_runtime.hpp>
#include <w1tn3ss/util/register_capture.hpp>
#include <w1tn3ss/util/stack_capture.hpp>

namespace w1xfer {
namespace {

uint64_t current_timestamp() {
  return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                   std::chrono::steady_clock::now().time_since_epoch()
                               )
                                   .count());
}

uint64_t read_link_register(QBDI::GPRState* gpr) {
#if defined(QBDI_ARCH_AARCH64)
  return gpr->lr;
#elif defined(QBDI_ARCH_ARM)
  return gpr->r14;
#else
  (void)gpr;
  return 0;
#endif
}

uint64_t resolve_callsite(QBDI::GPRState* gpr, const std::optional<w1::util::stack_info>& stack_info) {
  uint64_t link = read_link_register(gpr);
  if (link != 0) {
    return link;
  }
  if (stack_info && stack_info->return_address != 0) {
    return stack_info->return_address;
  }
  return 0;
}

transfer_registers to_registers(const w1::util::register_state& regs) {
  transfer_registers out;
  out.values = regs.get_all_registers();
  return out;
}

transfer_stack to_stack(const w1::util::stack_info& stack) {
  transfer_stack out;
  out.stack_pointer = stack.stack_pointer;
  out.frame_pointer = stack.frame_pointer;
  out.return_address = stack.return_address;
  out.values.reserve(stack.values.size());
  for (const auto& entry : stack.values) {
    if (entry.is_valid) {
      out.values.push_back(entry.value);
    }
  }
  return out;
}

transfer_api_info to_api_info(const w1::abi::api_event& event) {
  transfer_api_info info;
  info.category = w1::abi::to_string(event.category);
  info.description = event.description;
  info.formatted_call = event.formatted_call;
  info.analysis_complete = event.analysis_complete;
  info.has_return_value = event.has_return_value;

  info.arguments.reserve(event.arguments.size());
  for (const auto& arg : event.arguments) {
    transfer_api_argument out;
    out.raw_value = arg.raw_value;
    out.name = arg.param_name;
    out.type = w1::abi::to_string(arg.param_type);
    out.interpreted_value = arg.interpreted_value;
    out.is_pointer = arg.is_pointer;
    info.arguments.push_back(std::move(out));
  }

  if (event.return_value.has_value()) {
    const auto& ret = event.return_value.value();
    transfer_api_return out;
    out.raw_value = ret.raw_value;
    out.type = w1::abi::to_string(ret.param_type);
    out.interpreted_value = ret.interpreted_value;
    out.is_pointer = ret.is_pointer;
    out.is_null = (ret.interpreted_value == "NULL");
    info.return_value = out;
  }

  return info;
}

} // namespace

transfer_pipeline::transfer_pipeline(const transfer_config& config) : config_(config) {
  if (!config_.output.path.empty()) {
    writer_ = std::make_unique<transfer_writer_jsonl>(config_.output.path, config_.output.emit_metadata);
  }

  if (config_.enrich.analyze_apis) {
    w1::abi::analyzer_config cfg;
    cfg.extract_arguments = true;
    cfg.format_calls = true;
    cfg.max_string_length = 256;
    api_dispatcher_ = std::make_unique<w1::abi::api_dispatcher>(cfg);
  }
}

void transfer_pipeline::initialize_modules() {
  if (modules_initialized_) {
    return;
  }

  auto modules = scanner_.scan_executable_modules();
  module_index_.rebuild_from_modules(std::move(modules));
  symbol_lookup_.initialize(module_index_);

  if (api_dispatcher_) {
    api_dispatcher_->initialize(module_index_);
  }

  modules_initialized_ = true;
}

void transfer_pipeline::ensure_modules_initialized() {
  bool needs_modules = config_.enrich.modules || config_.enrich.symbols || config_.enrich.analyze_apis;
  bool needs_metadata = writer_ && config_.output.emit_metadata;
  if (!modules_initialized_ && (needs_modules || needs_metadata)) {
    initialize_modules();
  }
}

void transfer_pipeline::update_call_depth(transfer_type type) {
  if (type == transfer_type::CALL) {
    stats_.current_call_depth++;
    if (stats_.current_call_depth > stats_.max_call_depth) {
      stats_.max_call_depth = stats_.current_call_depth;
    }
  } else if (type == transfer_type::RETURN && stats_.current_call_depth > 0) {
    stats_.current_call_depth--;
  }
}

void transfer_pipeline::record_call(
    uint64_t source_addr, uint64_t target_addr, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  record_transfer(transfer_type::CALL, source_addr, target_addr, vm, state, gpr, fpr);
}

void transfer_pipeline::record_return(
    uint64_t source_addr, uint64_t target_addr, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  record_transfer(transfer_type::RETURN, source_addr, target_addr, vm, state, gpr, fpr);
}

void transfer_pipeline::maybe_write_record(const transfer_record& record) {
  if (!writer_ || !writer_->is_open()) {
    return;
  }

  if (config_.output.emit_metadata) {
    ensure_modules_initialized();
    writer_->ensure_metadata(module_index_);
  }

  writer_->write_record(record);
}

void transfer_pipeline::record_transfer(
    transfer_type type, uint64_t source_addr, uint64_t target_addr, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  if (type == transfer_type::CALL) {
    stats_.total_calls++;
    update_call_depth(transfer_type::CALL);

    unique_call_targets_.insert(target_addr);
    stats_.unique_call_targets = unique_call_targets_.size();
  } else {
    stats_.total_returns++;
    update_call_depth(transfer_type::RETURN);

    unique_return_sources_.insert(source_addr);
    stats_.unique_return_sources = unique_return_sources_.size();
  }

  ensure_modules_initialized();

  std::optional<w1::util::register_state> util_regs;
  if (config_.capture.registers || config_.capture.stack) {
    util_regs = w1::util::register_capturer::capture(gpr);
  }

  std::optional<w1::util::stack_info> stack_info;
  if (config_.capture.stack && util_regs) {
    stack_info = w1::util::stack_capturer::capture(vm, *util_regs);
    uint64_t link = read_link_register(gpr);
    if (link != 0) {
      stack_info->return_address = link;
    }
  }

  uint64_t resolved_source = source_addr;
  if (type == transfer_type::CALL) {
    uint64_t callsite = resolve_callsite(gpr, stack_info);
    if (callsite != 0) {
      resolved_source = callsite;
    }
  }

  transfer_record record;
  record.event.type = type;
  record.event.source_address = resolved_source;
  record.event.target_address = target_addr;
  record.event.instruction_index = instruction_index_++;
  record.event.timestamp = current_timestamp();
  record.event.thread_id = w1::runtime::threading::current_native_thread_id();
  record.event.call_depth = stats_.current_call_depth;

  if (config_.capture.registers && util_regs) {
    record.registers = to_registers(*util_regs);
  }

  if (config_.capture.stack && stack_info) {
    record.stack = to_stack(*stack_info);
  }

  if (config_.enrich.modules || config_.enrich.symbols) {
    record.source = build_endpoint(resolved_source);
    record.target = build_endpoint(target_addr);
  }

  if (config_.enrich.analyze_apis) {
    record.api =
        analyze_api_event(type, resolved_source, target_addr, vm, state, gpr, fpr, record.source, record.target);
  }

  maybe_write_record(record);
}

std::optional<transfer_endpoint> transfer_pipeline::build_endpoint(uint64_t address) const {
  if (!modules_initialized_) {
    return std::nullopt;
  }

  if (!config_.enrich.modules && !config_.enrich.symbols) {
    return std::nullopt;
  }

  transfer_endpoint endpoint;
  endpoint.address = address;

  const w1::util::module_info* module_info = module_index_.find_containing(address);
  if (module_info) {
    if (config_.enrich.modules) {
      endpoint.module_name = module_info->name;
      endpoint.module_offset = address - module_info->base_address;
    }
  }

  if (config_.enrich.symbols) {
    if (auto symbol = symbol_lookup_.resolve(address)) {
      transfer_symbol out;
      out.module_name = symbol->module_name;
      out.symbol_name = symbol->symbol_name;
      out.demangled_name = symbol->demangled_name;
      out.symbol_offset = symbol->symbol_offset;
      out.module_offset = symbol->module_offset;
      out.is_exported = symbol->is_exported;
      out.is_imported = symbol->is_imported;
      endpoint.symbol = out;

      if (endpoint.module_name.empty()) {
        endpoint.module_name = symbol->module_name;
        endpoint.module_offset = symbol->module_offset;
      }
    }
  }

  if (endpoint.module_name.empty() && !endpoint.symbol.has_value()) {
    return std::nullopt;
  }

  return endpoint;
}

std::optional<transfer_api_info> transfer_pipeline::analyze_api_event(
    transfer_type type, uint64_t source_addr, uint64_t target_addr, QBDI::VMInstanceRef vm,
    const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr,
    const std::optional<transfer_endpoint>& source,
    const std::optional<transfer_endpoint>& target
) {
  if (!api_dispatcher_) {
    return std::nullopt;
  }

  w1::abi::api_context ctx;
  ctx.vm = vm;
  ctx.vm_state = state;
  ctx.gpr_state = gpr;
  ctx.fpr_state = fpr;
  ctx.module_index = &module_index_;
  ctx.timestamp = static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());

  if (type == transfer_type::CALL) {
    ctx.call_address = source_addr;
    ctx.target_address = target_addr;
    if (target) {
      ctx.module_name = target->module_name;
      if (target->symbol) {
        ctx.symbol_name = target->symbol->symbol_name;
      }
    }

    auto event = api_dispatcher_->analyze_call(ctx);
    if (event) {
      return to_api_info(*event);
    }

  } else {
    ctx.call_address = target_addr;
    ctx.target_address = source_addr;
    if (source) {
      ctx.module_name = source->module_name;
      if (source->symbol) {
        ctx.symbol_name = source->symbol->symbol_name;
      }
    }

    auto event = api_dispatcher_->analyze_return(ctx);
    if (event) {
      return to_api_info(*event);
    }
  }

  return std::nullopt;
}

} // namespace w1xfer
