#include "transfer_collector.hpp"

#include <algorithm>
#include <chrono>
#include <unordered_set>

namespace w1xfer {

transfer_collector::transfer_collector(
    uint64_t max_entries, bool log_registers, bool log_stack_info, bool log_call_targets, bool analyze_apis,
    bool collect_trace
)
    : max_entries_(max_entries), instruction_count_(0), log_registers_(log_registers), log_stack_info_(log_stack_info),
      log_call_targets_(log_call_targets), analyze_apis_(analyze_apis), collect_trace_(collect_trace),
      trace_overflow_(false), modules_initialized_(false) {

  if (collect_trace_) {
    trace_.reserve(std::min(max_entries_, static_cast<uint64_t>(10000)));
  }

  // initialize stats
  stats_.total_calls = 0;
  stats_.total_returns = 0;
  stats_.unique_call_targets = 0;
  stats_.unique_return_sources = 0;
  stats_.max_call_depth = 0;
  stats_.current_call_depth = 0;

  // create symbol enricher if call targets are being logged
  if (log_call_targets_) {
    symbol_enricher_ = std::make_unique<symbol_enricher>();
  }

  // create API listener if API analysis is enabled
  if (analyze_apis_) {
    w1::abi::analyzer_config cfg;
    cfg.extract_arguments = true;
    cfg.format_calls = true;
    cfg.max_string_length = 256;
    api_listener_ = std::make_unique<w1::abi::api_listener>(cfg);
  }
}

void transfer_collector::record_call(
    uint64_t source_addr, uint64_t target_addr, QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  stats_.total_calls++;
  update_call_depth(transfer_type::CALL);

  // check if we should skip trace collection (but still do analysis)
  bool should_collect = should_collect_trace();
  if (collect_trace_ && !should_collect) {
    trace_overflow_ = true;
  }

  transfer_entry entry = create_base_entry(transfer_type::CALL, source_addr, target_addr);
  entry.instruction_count = instruction_count_++;

  populate_entry_details(entry, source_addr, target_addr, vm, gpr);

  // perform API analysis if enabled
  if (analyze_apis_ && api_listener_) {
    w1::abi::api_context ctx;
    ctx.call_address = source_addr;
    ctx.target_address = target_addr;
    ctx.module_name = entry.target_module;
    ctx.symbol_name = entry.target_symbol.symbol_name;
    ctx.vm = vm;
    ctx.vm_state = state;
    ctx.gpr_state = gpr;
    ctx.fpr_state = fpr;
    ctx.module_index = &index_;
    ctx.timestamp = entry.timestamp;
    
    // directly analyze the call
    if (auto api_event = api_listener_->analyze_call(ctx)) {
      on_api_event(*api_event, entry);
    }
  }

  // only add to trace if collection is enabled and we haven't overflowed
  if (should_collect) {
    trace_.push_back(entry);
  }
}

void transfer_collector::record_return(
    uint64_t source_addr, uint64_t target_addr, QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  stats_.total_returns++;
  update_call_depth(transfer_type::RETURN);

  // check if we should skip trace collection (but still do analysis)
  bool should_collect = should_collect_trace();
  if (collect_trace_ && !should_collect) {
    trace_overflow_ = true;
  }

  transfer_entry entry = create_base_entry(transfer_type::RETURN, source_addr, target_addr);
  entry.instruction_count = instruction_count_++;

  populate_entry_details(entry, source_addr, target_addr, vm, gpr);

  // perform return value analysis if enabled
  if (analyze_apis_ && api_listener_) {
    w1::abi::api_context ctx;
    ctx.call_address = target_addr;   // where we're returning to
    ctx.target_address = source_addr; // the function we're returning from
    ctx.module_name = entry.source_module;
    ctx.symbol_name = entry.source_symbol.symbol_name;
    ctx.vm = vm;
    ctx.vm_state = state;
    ctx.gpr_state = gpr;
    ctx.fpr_state = fpr;
    ctx.module_index = &index_;
    ctx.timestamp = entry.timestamp;
    
    // directly analyze the return
    if (auto api_event = api_listener_->analyze_return(ctx)) {
      on_api_event(*api_event, entry);
    }
  }

  // only add to trace if collection is enabled and we haven't overflowed
  if (should_collect) {
    trace_.push_back(entry);
  }
}

w1xfer_report transfer_collector::build_report() const {
  w1xfer_report report;
  report.stats = stats_;
  if (collect_trace_) {
    report.trace = trace_;
  }

  // calculate unique targets and sources
  std::unordered_set<uint64_t> unique_call_targets;
  std::unordered_set<uint64_t> unique_return_sources;

  for (const auto& entry : trace_) {
    if (entry.type == transfer_type::CALL) {
      unique_call_targets.insert(entry.target_address);
    } else {
      unique_return_sources.insert(entry.source_address);
    }
  }

  report.stats.unique_call_targets = unique_call_targets.size();
  report.stats.unique_return_sources = unique_return_sources.size();

  return report;
}

// helper function to convert our utility register_state to w1xfer register_state for JSON
static register_state convert_register_state(const w1::util::register_state& util_regs) {
  register_state regs;
  regs.registers = util_regs.get_all_registers();
  return regs;
}

// helper function to convert our utility stack_info to w1xfer stack_info for JSON
static stack_info convert_stack_info(const w1::util::stack_info& util_stack) {
  stack_info stack;
  stack.stack_pointer = util_stack.stack_pointer;
  stack.frame_pointer = util_stack.frame_pointer;
  stack.return_address = util_stack.return_address;

  // extract stack values from the captured entries
  stack.stack_values.reserve(util_stack.values.size());
  for (const auto& entry : util_stack.values) {
    if (entry.is_valid) {
      stack.stack_values.push_back(entry.value);
    }
  }

  return stack;
}

void transfer_collector::initialize_module_tracking() {
  if (modules_initialized_) {
    return;
  }

  // scan all executable modules
  auto modules = scanner_.scan_executable_modules();

  // rebuild index with all modules for fast lookup
  index_.rebuild_from_modules(std::move(modules));

  // initialize symbol enricher with the module index
  if (symbol_enricher_) {
    symbol_enricher_->initialize(index_);
  }

  // initialize API listener with the module index
  if (api_listener_) {
    api_listener_->initialize(index_);
  }

  modules_initialized_ = true;
}

std::string transfer_collector::get_module_name(uint64_t address) const {
  if (address == 0) {
    return "unknown";
  }

  // ensure modules are initialized before lookup
  if (!modules_initialized_) {
    // lazy initialization - cast away const for initialization
    const_cast<transfer_collector*>(this)->initialize_module_tracking();
  }

  // fast lookup using module range index
  auto module_info = index_.find_containing(address);
  if (module_info) {
    return module_info->name;
  }

  // fallback for addresses not in any known module
  return "unknown";
}

uint64_t transfer_collector::get_timestamp() const {
  auto now = std::chrono::steady_clock::now();
  return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
}

void transfer_collector::update_call_depth(transfer_type type) {
  if (type == transfer_type::CALL) {
    stats_.current_call_depth++;
    stats_.max_call_depth = std::max(stats_.max_call_depth, stats_.current_call_depth);
  } else if (type == transfer_type::RETURN && stats_.current_call_depth > 0) {
    stats_.current_call_depth--;
  }
}

symbol_info transfer_collector::enrich_symbol(uint64_t address) const {
  symbol_info info{};

  if (!symbol_enricher_) {
    return info;
  }

  auto enriched = symbol_enricher_->enrich_address(address);
  if (enriched) {
    info.symbol_name = enriched->symbol_name;
    info.demangled_name = enriched->demangled_name;
    info.symbol_offset = enriched->symbol_offset;
    info.module_offset = enriched->module_offset;
    info.is_exported = enriched->is_exported;
    info.is_imported = enriched->is_imported;
  }

  return info;
}

bool transfer_collector::should_collect_trace() const {
  return collect_trace_ && !trace_overflow_ && trace_.size() < max_entries_;
}

transfer_entry transfer_collector::create_base_entry(
    transfer_type type, uint64_t source_addr, uint64_t target_addr
) const {
  transfer_entry entry;
  entry.type = type;
  entry.source_address = source_addr;
  entry.target_address = target_addr;
  entry.timestamp = get_timestamp();
  entry.instruction_count = instruction_count_;
  return entry;
}

void transfer_collector::populate_entry_details(
    transfer_entry& entry, uint64_t source_addr, uint64_t target_addr, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr
) const {
  if (log_registers_) {
    // use our register capture utility
    auto util_regs = w1::util::register_capturer::capture(gpr);
    entry.registers = convert_register_state(util_regs);
  }

  if (log_stack_info_) {
    // use our stack capture utility
    auto util_regs = w1::util::register_capturer::capture(gpr);
    auto util_stack = w1::util::stack_capturer::capture(vm, util_regs);
    entry.stack = convert_stack_info(util_stack);
  }

  if (log_call_targets_) {
    entry.source_module = get_module_name(source_addr);
    entry.target_module = get_module_name(target_addr);

    if (symbol_enricher_) {
      entry.source_symbol = enrich_symbol(source_addr);
      entry.target_symbol = enrich_symbol(target_addr);
    }
  }
}

// format_interpreted_value is now replaced by w1::util::value_formatter

void transfer_collector::on_api_event(const w1::abi::api_event& event, transfer_entry& entry) {
  // convert api_event data to transfer_entry api_analysis format
  entry.api_info.api_category = event.category == w1::abi::api_info::category::UNKNOWN
                                    ? ""
                                    : std::to_string(static_cast<int>(event.category));
  entry.api_info.description = event.description;
  entry.api_info.formatted_call = event.formatted_call;
  entry.api_info.analysis_complete = event.analysis_complete;
  
  // convert arguments
  entry.api_info.arguments.clear();
  for (const auto& arg : event.arguments) {
    api_argument api_arg;
    api_arg.raw_value = arg.raw_value;
    api_arg.param_name = arg.param_name;
    api_arg.param_type = std::to_string(static_cast<int>(arg.param_type));
    api_arg.is_pointer = arg.is_pointer;
    api_arg.interpreted_value = arg.interpreted_value;
    entry.api_info.arguments.push_back(api_arg);
  }
  
  // handle return value if present
  if (event.type == w1::abi::api_event::event_type::RETURN && event.return_value.has_value()) {
    const auto& ret_val = event.return_value.value();
    entry.api_info.has_return_value = true;
    entry.api_info.return_value.raw_value = ret_val.raw_value;
    entry.api_info.return_value.param_type = std::to_string(static_cast<int>(ret_val.param_type));
    entry.api_info.return_value.is_pointer = ret_val.is_pointer;
    entry.api_info.return_value.interpreted_value = ret_val.interpreted_value;
    entry.api_info.return_value.is_null = (ret_val.interpreted_value == "NULL");
  } else {
    entry.api_info.has_return_value = false;
  }
}

} // namespace w1xfer