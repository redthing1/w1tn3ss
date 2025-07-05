#include "transfer_collector.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <unordered_set>

namespace w1xfer {

transfer_collector::transfer_collector(uint64_t max_entries, bool log_registers, bool log_stack_info, bool log_call_targets)
    : max_entries_(max_entries), instruction_count_(0), log_registers_(log_registers), 
      log_stack_info_(log_stack_info), log_call_targets_(log_call_targets), trace_overflow_(false), modules_initialized_(false) {
  
  trace_.reserve(std::min(max_entries_, static_cast<uint64_t>(10000)));
  
  // initialize stats
  stats_.total_calls = 0;
  stats_.total_returns = 0;
  stats_.unique_call_targets = 0;
  stats_.unique_return_sources = 0;
  stats_.max_call_depth = 0;
  stats_.current_call_depth = 0;
}

void transfer_collector::record_call(uint64_t source_addr, uint64_t target_addr, QBDI::VMInstanceRef vm,
                                   const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr) {
  stats_.total_calls++;
  update_call_depth(transfer_type::CALL);

  if (trace_overflow_ || trace_.size() >= max_entries_) {
    trace_overflow_ = true;
    return;
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
  }

  trace_.push_back(entry);
}

void transfer_collector::record_return(uint64_t source_addr, uint64_t target_addr, QBDI::VMInstanceRef vm,
                                     const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr) {
  stats_.total_returns++;
  update_call_depth(transfer_type::RETURN);

  if (trace_overflow_ || trace_.size() >= max_entries_) {
    trace_overflow_ = true;
    return;
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
  }

  trace_.push_back(entry);
}

w1xfer_report transfer_collector::build_report() const {
  w1xfer_report report;
  report.stats = stats_;
  report.trace = trace_;

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
  regs.x0 = gpr->x0;   regs.x1 = gpr->x1;   regs.x2 = gpr->x2;   regs.x3 = gpr->x3;
  regs.x4 = gpr->x4;   regs.x5 = gpr->x5;   regs.x6 = gpr->x6;   regs.x7 = gpr->x7;
  regs.x8 = gpr->x8;   regs.x9 = gpr->x9;   regs.x10 = gpr->x10; regs.x11 = gpr->x11;
  regs.x12 = gpr->x12; regs.x13 = gpr->x13; regs.x14 = gpr->x14; regs.x15 = gpr->x15;
  regs.x16 = gpr->x16; regs.x17 = gpr->x17; regs.x18 = gpr->x18; regs.x19 = gpr->x19;
  regs.x20 = gpr->x20; regs.x21 = gpr->x21; regs.x22 = gpr->x22; regs.x23 = gpr->x23;
  regs.x24 = gpr->x24; regs.x25 = gpr->x25; regs.x26 = gpr->x26; regs.x27 = gpr->x27;
  regs.x28 = gpr->x28; regs.x29 = gpr->x29;
  regs.lr = gpr->lr;
  regs.sp = gpr->sp;
  regs.nzcv = gpr->nzcv;
  regs.pc = gpr->pc;
  
#elif defined(QBDI_ARCH_ARM)
  // arm32 register capture
  regs.r0 = gpr->r0;   regs.r1 = gpr->r1;   regs.r2 = gpr->r2;   regs.r3 = gpr->r3;
  regs.r4 = gpr->r4;   regs.r5 = gpr->r5;   regs.r6 = gpr->r6;   regs.r7 = gpr->r7;
  regs.r8 = gpr->r8;   regs.r9 = gpr->r9;   regs.r10 = gpr->r10; regs.r11 = gpr->r11;
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

} // namespace w1xfer