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

  // Create symbol enricher if call targets are being logged
  if (log_call_targets_) {
    symbol_enricher_ = std::make_unique<symbol_enricher>();
  }

  // Create API analyzer if API analysis is enabled
  if (analyze_apis_) {
    w1::abi::analyzer_config cfg;
    cfg.extract_arguments = true;
    cfg.format_calls = true;
    cfg.max_string_length = 256;
    api_analyzer_ = std::make_unique<w1::abi::api_analyzer>(cfg);
  }
}

void transfer_collector::record_call(
    uint64_t source_addr, uint64_t target_addr, QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  stats_.total_calls++;
  update_call_depth(transfer_type::CALL);

  // Check if we should skip trace collection (but still do analysis)
  bool should_collect = should_collect_trace();
  if (collect_trace_ && !should_collect) {
    trace_overflow_ = true;
  }

  transfer_entry entry = create_base_entry(transfer_type::CALL, source_addr, target_addr);
  entry.instruction_count = instruction_count_++;

  populate_entry_details(entry, source_addr, target_addr, vm, gpr);

  // Perform API analysis if enabled
  if (analyze_apis_ && api_analyzer_) {
    // Use value formatter for consistent formatting
    w1::util::value_formatter::format_options fmt_opts;
    fmt_opts.max_string_length = 256;
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

    auto analysis = api_analyzer_->analyze_call(ctx);

    // Convert analysis result to our format
    entry.api_info.api_category = analysis.category == w1::abi::api_info::category::UNKNOWN
                                      ? ""
                                      : std::to_string(static_cast<int>(analysis.category));
    entry.api_info.description = analysis.description;
    entry.api_info.formatted_call = analysis.formatted_call;
    entry.api_info.analysis_complete = analysis.analysis_complete;

    // Convert arguments
    for (const auto& arg : analysis.arguments) {
      api_argument api_arg;
      api_arg.raw_value = arg.raw_value;
      api_arg.param_name = arg.param_name;
      api_arg.param_type = std::to_string(static_cast<int>(arg.param_type));
      api_arg.is_pointer = arg.is_valid_pointer;

      // Format interpreted value using our formatter utility
      if (!arg.string_preview.empty()) {
        api_arg.interpreted_value = w1::util::value_formatter::format_string(arg.string_preview, fmt_opts);
      } else if (arg.is_null_pointer) {
        api_arg.interpreted_value = "NULL";
      } else if (std::holds_alternative<std::string>(arg.interpreted_value)) {
        api_arg.interpreted_value =
            w1::util::value_formatter::format_string(std::get<std::string>(arg.interpreted_value), fmt_opts);
      } else if (std::holds_alternative<bool>(arg.interpreted_value)) {
        api_arg.interpreted_value = w1::util::value_formatter::format_bool(std::get<bool>(arg.interpreted_value));
      } else if (std::holds_alternative<std::vector<uint8_t>>(arg.interpreted_value)) {
        api_arg.interpreted_value =
            w1::util::value_formatter::format_buffer(std::get<std::vector<uint8_t>>(arg.interpreted_value), fmt_opts);
      } else {
        // fallback to type-based formatting
        auto value_type = w1::util::value_formatter::value_type::UNKNOWN;
        if (arg.param_type == w1::abi::param_info::type::BOOLEAN) {
          value_type = w1::util::value_formatter::value_type::BOOLEAN;
        } else if (arg.param_type == w1::abi::param_info::type::ERROR_CODE) {
          value_type = w1::util::value_formatter::value_type::ERROR_CODE;
        } else if (arg.is_valid_pointer) {
          value_type = w1::util::value_formatter::value_type::POINTER;
        }
        api_arg.interpreted_value = w1::util::value_formatter::format_typed_value(arg.raw_value, value_type, fmt_opts);
      }

      entry.api_info.arguments.push_back(api_arg);
    }

    // Track this call for later return value analysis if we found API info
    if (analysis.analysis_complete && analysis.category != w1::abi::api_info::category::UNKNOWN) {
      // Look up the full API info from the database for return value analysis
      if (auto api_info = api_analyzer_->get_api_db().lookup(analysis.symbol_name)) {
        if (api_info->return_value.param_type != w1::abi::param_info::type::VOID) {
          pending_call pending;
          pending.call_target_address = target_addr;
          pending.target_symbol_name = entry.target_symbol.symbol_name;
          pending.target_module = entry.target_module;
          pending.api_info = *api_info;
          pending.timestamp = entry.timestamp;
          call_stack_.push_back(pending);
        }
      }
    }
  }

  // Only add to trace if collection is enabled and we haven't overflowed
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

  // Check if we should skip trace collection (but still do analysis)
  bool should_collect = should_collect_trace();
  if (collect_trace_ && !should_collect) {
    trace_overflow_ = true;
  }

  transfer_entry entry = create_base_entry(transfer_type::RETURN, source_addr, target_addr);
  entry.instruction_count = instruction_count_++;

  populate_entry_details(entry, source_addr, target_addr, vm, gpr);

  // Perform return value analysis if enabled and we have a matching call
  if (analyze_apis_ && api_analyzer_ && !call_stack_.empty()) {
    // Find matching call based on source address (the function we're returning from)
    auto call_it = std::find_if(call_stack_.rbegin(), call_stack_.rend(), [source_addr](const pending_call& call) {
      return call.call_target_address == source_addr;
    });

    if (call_it != call_stack_.rend()) {
      // Build context for return value analysis
      w1::abi::api_context ctx;
      ctx.call_address = target_addr;   // where we're returning to
      ctx.target_address = source_addr; // the function we're returning from
      ctx.module_name = call_it->target_module;
      ctx.symbol_name = call_it->target_symbol_name;
      ctx.vm = vm;
      ctx.vm_state = state;
      ctx.gpr_state = gpr;
      ctx.fpr_state = fpr;
      ctx.module_index = &index_;
      ctx.timestamp = entry.timestamp;

      // Create analysis result with call info and analyze return
      w1::abi::api_analysis_result return_analysis;
      return_analysis.symbol_name = call_it->target_symbol_name;
      return_analysis.module_name = call_it->target_module;
      return_analysis.category = call_it->api_info.api_category;
      return_analysis.description = call_it->api_info.description;
      return_analysis.analysis_complete = true;

      api_analyzer_->analyze_return(return_analysis, ctx);

      // Copy API information from the call
      entry.api_info.api_category = std::to_string(static_cast<int>(call_it->api_info.api_category));
      entry.api_info.description = call_it->api_info.description;
      entry.api_info.analysis_complete = true;
      entry.api_info.has_return_value = true;

      // Extract and format return value
      const auto& ret_val = return_analysis.return_value;
      entry.api_info.return_value.raw_value = ret_val.raw_value;
      entry.api_info.return_value.param_type = std::to_string(static_cast<int>(ret_val.param_type));
      entry.api_info.return_value.is_pointer = ret_val.is_valid_pointer;
      entry.api_info.return_value.is_null = ret_val.is_null_pointer;

      // Format interpreted value using our formatter utility
      w1::util::value_formatter::format_options fmt_opts;
      fmt_opts.max_string_length = 256;

      if (!ret_val.string_preview.empty()) {
        entry.api_info.return_value.interpreted_value =
            w1::util::value_formatter::format_string(ret_val.string_preview, fmt_opts);
      } else if (ret_val.is_null_pointer) {
        entry.api_info.return_value.interpreted_value = "NULL";
      } else if (std::holds_alternative<std::string>(ret_val.interpreted_value)) {
        entry.api_info.return_value.interpreted_value =
            w1::util::value_formatter::format_string(std::get<std::string>(ret_val.interpreted_value), fmt_opts);
      } else if (std::holds_alternative<bool>(ret_val.interpreted_value)) {
        entry.api_info.return_value.interpreted_value =
            w1::util::value_formatter::format_bool(std::get<bool>(ret_val.interpreted_value));
      } else {
        // fallback to type-based formatting
        auto value_type = w1::util::value_formatter::value_type::UNKNOWN;
        if (ret_val.param_type == w1::abi::param_info::type::BOOLEAN) {
          value_type = w1::util::value_formatter::value_type::BOOLEAN;
        } else if (ret_val.param_type == w1::abi::param_info::type::ERROR_CODE) {
          value_type = w1::util::value_formatter::value_type::ERROR_CODE;
        } else if (ret_val.is_valid_pointer) {
          value_type = w1::util::value_formatter::value_type::POINTER;
        }
        entry.api_info.return_value.interpreted_value =
            w1::util::value_formatter::format_typed_value(ret_val.raw_value, value_type, fmt_opts);
      }

      // Build formatted call string with return value
      entry.api_info.formatted_call =
          call_it->target_symbol_name + "() = " + entry.api_info.return_value.interpreted_value;

      // Remove the call from stack (convert reverse iterator to forward iterator for erase)
      call_stack_.erase(std::next(call_it).base());
    }
  }

  // Only add to trace if collection is enabled and we haven't overflowed
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

  // Initialize symbol enricher with the module index
  if (symbol_enricher_) {
    symbol_enricher_->initialize(index_);
  }

  // Initialize API analyzer with the module index
  if (api_analyzer_) {
    api_analyzer_->initialize(index_);
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

} // namespace w1xfer