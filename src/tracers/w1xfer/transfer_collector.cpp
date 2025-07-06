#include "transfer_collector.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <cstdio>
#include <sstream>
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
  bool should_collect_trace = collect_trace_ && !trace_overflow_ && trace_.size() < max_entries_;
  if (collect_trace_ && !should_collect_trace) {
    trace_overflow_ = true;
  }

  transfer_entry entry;
  entry.type = transfer_type::CALL;
  entry.source_address = source_addr;
  entry.target_address = target_addr;
  entry.timestamp = get_timestamp();
  entry.instruction_count = instruction_count_++;

  if (log_registers_) {
    entry.registers = capture_registers(gpr);
  }

  if (log_stack_info_) {
    entry.stack = capture_stack_info(vm, gpr);
  }

  if (log_call_targets_) {
    entry.source_module = get_module_name(source_addr);
    entry.target_module = get_module_name(target_addr);

    // Enrich with symbol information
    if (symbol_enricher_) {
      entry.source_symbol = enrich_symbol(source_addr);
      entry.target_symbol = enrich_symbol(target_addr);
    }
  }

  // Perform API analysis if enabled
  if (analyze_apis_ && api_analyzer_) {
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

      // Format interpreted value
      if (!arg.string_preview.empty()) {
        api_arg.interpreted_value = "\"" + arg.string_preview + "\"";
      } else if (arg.is_null_pointer) {
        api_arg.interpreted_value = "NULL";
      } else if (arg.param_type == w1::abi::param_info::type::BOOLEAN) {
        api_arg.interpreted_value = arg.raw_value ? "true" : "false";
      } else {
        std::stringstream ss;
        ss << "0x" << std::hex << arg.raw_value;
        api_arg.interpreted_value = ss.str();
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
  if (should_collect_trace) {
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
  bool should_collect_trace = collect_trace_ && !trace_overflow_ && trace_.size() < max_entries_;
  if (collect_trace_ && !should_collect_trace) {
    trace_overflow_ = true;
  }

  transfer_entry entry;
  entry.type = transfer_type::RETURN;
  entry.source_address = source_addr;
  entry.target_address = target_addr;
  entry.timestamp = get_timestamp();
  entry.instruction_count = instruction_count_++;

  if (log_registers_) {
    entry.registers = capture_registers(gpr);
  }

  if (log_stack_info_) {
    entry.stack = capture_stack_info(vm, gpr);
  }

  if (log_call_targets_) {
    entry.source_module = get_module_name(source_addr);
    entry.target_module = get_module_name(target_addr);

    // Enrich with symbol information
    if (symbol_enricher_) {
      entry.source_symbol = enrich_symbol(source_addr);
      entry.target_symbol = enrich_symbol(target_addr);
    }
  }

  // Perform return value analysis if enabled and we have a matching call
  if (analyze_apis_ && api_analyzer_ && !call_stack_.empty()) {
    // Find matching call based on source address (the function we're returning from)
    auto call_it = std::find_if(call_stack_.rbegin(), call_stack_.rend(), 
      [source_addr](const pending_call& call) {
        return call.call_target_address == source_addr;
      });

    if (call_it != call_stack_.rend()) {
      // Build context for return value analysis
      w1::abi::api_context ctx;
      ctx.call_address = target_addr; // where we're returning to
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

      // Format interpreted value
      if (!ret_val.string_preview.empty()) {
        entry.api_info.return_value.interpreted_value = "\"" + ret_val.string_preview + "\"";
      } else if (ret_val.is_null_pointer) {
        entry.api_info.return_value.interpreted_value = "NULL";
      } else if (ret_val.param_type == w1::abi::param_info::type::BOOLEAN) {
        entry.api_info.return_value.interpreted_value = ret_val.raw_value ? "true" : "false";
      } else if (ret_val.param_type == w1::abi::param_info::type::ERROR_CODE) {
        std::stringstream ss;
        ss << "0x" << std::hex << ret_val.raw_value << " (" << static_cast<int64_t>(ret_val.raw_value) << ")";
        entry.api_info.return_value.interpreted_value = ss.str();
      } else {
        std::stringstream ss;
        ss << "0x" << std::hex << ret_val.raw_value;
        entry.api_info.return_value.interpreted_value = ss.str();
      }

      // Build formatted call string with return value
      entry.api_info.formatted_call = call_it->target_symbol_name + "() = " + entry.api_info.return_value.interpreted_value;

      // Remove the call from stack (convert reverse iterator to forward iterator for erase)
      call_stack_.erase(std::next(call_it).base());
    }
  }

  // Only add to trace if collection is enabled and we haven't overflowed
  if (should_collect_trace) {
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

register_state transfer_collector::capture_registers(QBDI::GPRState* gpr) const {
  register_state regs;

  // capture architecture-specific registers with conditional compilation
#if defined(QBDI_ARCH_X86_64)
  // x86_64 register capture
  regs.rax = gpr->rax;
  regs.rbx = gpr->rbx;
  regs.rcx = gpr->rcx;
  regs.rdx = gpr->rdx;
  regs.rsi = gpr->rsi;
  regs.rdi = gpr->rdi;
  regs.r8 = gpr->r8;
  regs.r9 = gpr->r9;
  regs.r10 = gpr->r10;
  regs.r11 = gpr->r11;
  regs.r12 = gpr->r12;
  regs.r13 = gpr->r13;
  regs.r14 = gpr->r14;
  regs.r15 = gpr->r15;
  regs.rbp = gpr->rbp;
  regs.rsp = gpr->rsp;
  regs.rip = gpr->rip;
  regs.eflags = gpr->eflags;
  regs.fs = gpr->fs;
  regs.gs = gpr->gs;

#elif defined(QBDI_ARCH_AARCH64)
  // aarch64 register capture
  regs.x0 = gpr->x0;
  regs.x1 = gpr->x1;
  regs.x2 = gpr->x2;
  regs.x3 = gpr->x3;
  regs.x4 = gpr->x4;
  regs.x5 = gpr->x5;
  regs.x6 = gpr->x6;
  regs.x7 = gpr->x7;
  regs.x8 = gpr->x8;
  regs.x9 = gpr->x9;
  regs.x10 = gpr->x10;
  regs.x11 = gpr->x11;
  regs.x12 = gpr->x12;
  regs.x13 = gpr->x13;
  regs.x14 = gpr->x14;
  regs.x15 = gpr->x15;
  regs.x16 = gpr->x16;
  regs.x17 = gpr->x17;
  regs.x18 = gpr->x18;
  regs.x19 = gpr->x19;
  regs.x20 = gpr->x20;
  regs.x21 = gpr->x21;
  regs.x22 = gpr->x22;
  regs.x23 = gpr->x23;
  regs.x24 = gpr->x24;
  regs.x25 = gpr->x25;
  regs.x26 = gpr->x26;
  regs.x27 = gpr->x27;
  regs.x28 = gpr->x28;
  regs.x29 = gpr->x29;
  regs.lr = gpr->lr;
  regs.sp = gpr->sp;
  regs.nzcv = gpr->nzcv;
  regs.pc = gpr->pc;

#elif defined(QBDI_ARCH_ARM)
  // arm32 register capture
  regs.r0 = gpr->r0;
  regs.r1 = gpr->r1;
  regs.r2 = gpr->r2;
  regs.r3 = gpr->r3;
  regs.r4 = gpr->r4;
  regs.r5 = gpr->r5;
  regs.r6 = gpr->r6;
  regs.r7 = gpr->r7;
  regs.r8 = gpr->r8;
  regs.r9 = gpr->r9;
  regs.r10 = gpr->r10;
  regs.r11 = gpr->r11;
  regs.r12 = gpr->r12;
  regs.sp = gpr->sp;
  regs.lr = gpr->lr;
  regs.pc = gpr->pc;
  regs.cpsr = gpr->cpsr;

#elif defined(QBDI_ARCH_X86)
  // x86 32-bit register capture
  regs.eax = gpr->eax;
  regs.ebx = gpr->ebx;
  regs.ecx = gpr->ecx;
  regs.edx = gpr->edx;
  regs.esi = gpr->esi;
  regs.edi = gpr->edi;
  regs.ebp = gpr->ebp;
  regs.esp = gpr->esp;
  regs.eip = gpr->eip;
  regs.eflags = gpr->eflags;

#else
  // fallback for unknown architectures - copy raw data
  std::memcpy(regs.unknown_register_data, gpr, std::min(sizeof(regs.unknown_register_data), sizeof(QBDI::GPRState)));
#endif

  return regs;
}

stack_info transfer_collector::capture_stack_info(QBDI::VMInstanceRef vm, QBDI::GPRState* gpr) const {
  stack_info stack;

  // capture stack pointer across platforms
#if defined(QBDI_ARCH_X86_64)
  stack.stack_pointer = gpr->rsp;
#elif defined(QBDI_ARCH_AARCH64) || defined(QBDI_ARCH_ARM)
  stack.stack_pointer = gpr->sp;
#elif defined(QBDI_ARCH_X86)
  stack.stack_pointer = gpr->esp;
#else
  stack.stack_pointer = 0; // fallback
#endif

  // try to read return address and a few stack values
  QBDI::VM* vm_ptr = static_cast<QBDI::VM*>(vm);

  // read return address (at stack pointer for x64)
  uint64_t return_addr = 0;
  size_t read_bytes = vm_ptr->getInstMemoryAccess().size();
  if (read_bytes >= sizeof(uint64_t)) {
    // attempt to read from stack pointer
    // note: this is a simplified approach - real implementation would need proper memory access
    stack.return_address = return_addr;
  }

  // capture a few stack values around the stack pointer
  constexpr size_t stack_capture_size = 8;
  stack.stack_values.reserve(stack_capture_size);

  for (size_t i = 0; i < stack_capture_size; ++i) {
    // simplified - would need proper memory reading in real implementation
    stack.stack_values.push_back(0);
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

} // namespace w1xfer