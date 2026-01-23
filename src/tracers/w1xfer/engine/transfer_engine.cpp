#include "transfer_engine.hpp"

#include <chrono>
#include <string>
#include <utility>

namespace w1xfer {
namespace {

uint64_t current_timestamp() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count()
  );
}

uint64_t read_link_register(const QBDI::GPRState* gpr) {
#if defined(QBDI_ARCH_AARCH64)
  return gpr ? gpr->lr : 0;
#elif defined(QBDI_ARCH_ARM)
  return gpr ? gpr->r14 : 0;
#else
  (void) gpr;
  return 0;
#endif
}

uint64_t resolve_callsite(const QBDI::GPRState* gpr, const std::optional<w1::util::stack_info>& stack_info) {
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

} // namespace

transfer_engine::transfer_engine(transfer_config config) : config_(std::move(config)) {
  capture_registers_ = config_.capture.registers || config_.capture.stack || config_.enrich.analyze_apis;
  capture_stack_ = config_.capture.stack;
  enrich_modules_ = config_.enrich.modules;
  enrich_symbols_ = config_.enrich.symbols;
  analyze_apis_ = config_.enrich.analyze_apis;
  emit_metadata_ = config_.output.emit_metadata;

  if (!config_.output.path.empty()) {
    writer_ = std::make_unique<transfer_writer_jsonl>(config_.output.path, config_.output.emit_metadata);
  }

  if (analyze_apis_) {
    w1::analysis::abi_dispatcher_config cfg;
    cfg.enable_stack_reads = true;
    abi_dispatcher_ = std::make_unique<w1::analysis::abi_dispatcher>(cfg);
  }
}

void transfer_engine::configure(w1::runtime::module_catalog& modules) {
  modules_ = &modules;
  if (enrich_modules_ || enrich_symbols_ || emit_metadata_) {
    symbol_lookup_.set_module_catalog(modules_);
  }
}

void transfer_engine::attach(const w1::trace_context& ctx) {
  if (attached_) {
    return;
  }

  modules_ = &ctx.modules();
  memory_ = &ctx.memory();

  if (enrich_modules_ || enrich_symbols_ || emit_metadata_) {
    symbol_lookup_.set_module_catalog(modules_);
  }

  if (emit_metadata_ && writer_ && modules_) {
    writer_->ensure_metadata(*modules_);
  }

  attached_ = true;
}

void transfer_engine::shutdown() {
  if (writer_) {
    writer_->flush();
  }
}

bool transfer_engine::export_output() {
  const bool had_output = writer_ && writer_->is_open();
  if (writer_) {
    writer_->flush();
    writer_->close();
    writer_.reset();
  }
  return had_output;
}

void transfer_engine::update_call_depth(transfer_type type) {
  if (type == transfer_type::CALL) {
    stats_.current_call_depth++;
    if (stats_.current_call_depth > stats_.max_call_depth) {
      stats_.max_call_depth = stats_.current_call_depth;
    }
  } else if (type == transfer_type::RETURN && stats_.current_call_depth > 0) {
    stats_.current_call_depth--;
  }
}

void transfer_engine::record_call(
    const w1::trace_context& ctx, const w1::exec_transfer_event& event, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  (void) fpr;
  record_transfer(transfer_type::CALL, ctx, event, gpr, fpr);
}

void transfer_engine::record_return(
    const w1::trace_context& ctx, const w1::exec_transfer_event& event, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  (void) fpr;
  record_transfer(transfer_type::RETURN, ctx, event, gpr, fpr);
}

std::optional<transfer_endpoint> transfer_engine::resolve_endpoint(uint64_t address) const {
  return build_endpoint(address);
}

void transfer_engine::write_record(const transfer_record& record) {
  if (!writer_ || !writer_->is_open()) {
    return;
  }

  writer_->write_record(record);
}

void transfer_engine::record_transfer(
    transfer_type type, const w1::trace_context& ctx, const w1::exec_transfer_event& event, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  (void) fpr;
  if (type == transfer_type::CALL) {
    stats_.total_calls++;
    update_call_depth(transfer_type::CALL);
    unique_call_targets_.insert(event.target_address);
    stats_.unique_call_targets = unique_call_targets_.size();
  } else {
    stats_.total_returns++;
    update_call_depth(transfer_type::RETURN);
    unique_return_sources_.insert(event.source_address);
    stats_.unique_return_sources = unique_return_sources_.size();
  }

  if (!attached_) [[unlikely]] {
    attach(ctx);
  }

  std::optional<w1::util::register_state> regs;
  if (capture_registers_) {
    regs = w1::util::register_capturer::capture(gpr);
  }

  std::optional<w1::util::stack_info> stack_info;
  if (capture_stack_ && regs && memory_ &&
      regs->get_architecture() != w1::util::register_state::architecture::unknown) {
    stack_info = w1::util::stack_capturer::capture(*memory_, *regs);
  }

  uint64_t resolved_source = event.source_address;
  if (type == transfer_type::CALL) {
    uint64_t callsite = resolve_callsite(gpr, stack_info);
    if (callsite != 0) {
      resolved_source = callsite;
    }
  }

  transfer_record record;
  record.event.type = type;
  record.event.source_address = resolved_source;
  record.event.target_address = event.target_address;
  record.event.instruction_index = instruction_index_++;
  record.event.timestamp = current_timestamp();
  record.event.thread_id = ctx.thread_id();
  record.event.call_depth = stats_.current_call_depth;

  if (config_.capture.registers && regs) {
    record.registers = to_registers(*regs);
  }

  if (capture_stack_ && stack_info) {
    record.stack = to_stack(*stack_info);
  }

  if (enrich_modules_ || enrich_symbols_) {
    record.source = build_endpoint(resolved_source);
    record.target = build_endpoint(event.target_address);
  }

  if (analyze_apis_) {
    record.api = analyze_api_event(type, ctx, resolved_source, event.target_address, gpr);
  }

  write_record(record);
}

std::optional<transfer_endpoint> transfer_engine::build_endpoint(uint64_t address) const {
  if (!modules_) {
    return std::nullopt;
  }

  if (!enrich_modules_ && !enrich_symbols_) {
    return std::nullopt;
  }

  transfer_endpoint endpoint;
  endpoint.address = address;

  if (const auto* module = modules_->find_containing(address)) {
    if (enrich_modules_) {
      endpoint.module_name = module->name;
      endpoint.module_offset = address - module->base_address;
    }
  }

  if (enrich_symbols_) {
    if (auto symbol = symbol_lookup_.resolve(address); symbol && symbol->has_symbol) {
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

std::optional<transfer_api_info> transfer_engine::analyze_api_event(
    transfer_type type, const w1::trace_context& ctx, uint64_t source_addr, uint64_t target_addr, QBDI::GPRState* gpr
) {
  (void) ctx;
  (void) source_addr;
  (void) target_addr;

  if (!abi_dispatcher_ || !memory_ || !gpr) {
    return std::nullopt;
  }

  transfer_api_info info;
  info.category = "raw";
  info.description = "raw abi values";
  info.analysis_complete = false;
  info.formatted_call = "";

  if (type == transfer_type::CALL) {
    size_t arg_count = config_.enrich.api_argument_count;
    if (arg_count == 0) {
      arg_count = default_argument_count();
    }

    auto args = abi_dispatcher_->extract_arguments(*memory_, gpr, arg_count);
    info.arguments.reserve(args.size());
    for (size_t i = 0; i < args.size(); ++i) {
      const auto& arg = args[i];
      if (!arg.is_valid) {
        continue;
      }
      transfer_api_argument out;
      out.raw_value = arg.raw_value;
      out.name = "arg" + std::to_string(i);
      out.type = "raw";
      out.interpreted_value = "";
      out.is_pointer = false;
      info.arguments.push_back(std::move(out));
    }
  } else {
    transfer_api_return ret;
    ret.raw_value = abi_dispatcher_->extract_return_value(gpr);
    ret.type = "raw";
    ret.interpreted_value = "";
    ret.is_pointer = false;
    ret.is_null = ret.raw_value == 0;
    info.return_value = ret;
    info.has_return_value = true;
  }

  return info;
}

size_t transfer_engine::default_argument_count() const {
  if (!abi_dispatcher_) {
    return 0;
  }

  switch (abi_dispatcher_->kind()) {
  case w1::analysis::abi_kind::system_v_amd64:
    return 6;
  case w1::analysis::abi_kind::windows_amd64:
    return 4;
  case w1::analysis::abi_kind::aarch64:
    return 8;
  case w1::analysis::abi_kind::x86:
    return 4;
  default:
    return 0;
  }
}

} // namespace w1xfer
