#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <QBDI.h>
#include <common/ext/jsonstruct.hpp>
#include <w1tn3ss/util/module_range_index.hpp>
#include <w1tn3ss/util/module_scanner.hpp>

namespace w1xfer {

enum class transfer_type {
  CALL = 0,
  RETURN = 1
};

// cross-platform register state - architecture-specific with conditional compilation
struct register_state {
#if defined(QBDI_ARCH_X86_64)
  // x86_64 registers
  uint64_t rax, rbx, rcx, rdx, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15;
  uint64_t rbp, rsp, rip, eflags, fs, gs;
  
  JS_OBJECT(
    JS_MEMBER(rax), JS_MEMBER(rbx), JS_MEMBER(rcx), JS_MEMBER(rdx),
    JS_MEMBER(rsi), JS_MEMBER(rdi), JS_MEMBER(r8), JS_MEMBER(r9),
    JS_MEMBER(r10), JS_MEMBER(r11), JS_MEMBER(r12), JS_MEMBER(r13),
    JS_MEMBER(r14), JS_MEMBER(r15), JS_MEMBER(rbp), JS_MEMBER(rsp),
    JS_MEMBER(rip), JS_MEMBER(eflags), JS_MEMBER(fs), JS_MEMBER(gs)
  );
  
#elif defined(QBDI_ARCH_AARCH64)
  // aarch64 registers
  uint64_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
  uint64_t x16, x17, x18, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28, x29;
  uint64_t lr, sp, nzcv, pc;
  
  JS_OBJECT(
    JS_MEMBER(x0), JS_MEMBER(x1), JS_MEMBER(x2), JS_MEMBER(x3),
    JS_MEMBER(x4), JS_MEMBER(x5), JS_MEMBER(x6), JS_MEMBER(x7),
    JS_MEMBER(x8), JS_MEMBER(x9), JS_MEMBER(x10), JS_MEMBER(x11),
    JS_MEMBER(x12), JS_MEMBER(x13), JS_MEMBER(x14), JS_MEMBER(x15),
    JS_MEMBER(x16), JS_MEMBER(x17), JS_MEMBER(x18), JS_MEMBER(x19),
    JS_MEMBER(x20), JS_MEMBER(x21), JS_MEMBER(x22), JS_MEMBER(x23),
    JS_MEMBER(x24), JS_MEMBER(x25), JS_MEMBER(x26), JS_MEMBER(x27),
    JS_MEMBER(x28), JS_MEMBER(x29), JS_MEMBER(lr), JS_MEMBER(sp),
    JS_MEMBER(nzcv), JS_MEMBER(pc)
  );
  
#elif defined(QBDI_ARCH_ARM)
  // arm32 registers  
  uint32_t r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12;
  uint32_t sp, lr, pc, cpsr;
  
  JS_OBJECT(
    JS_MEMBER(r0), JS_MEMBER(r1), JS_MEMBER(r2), JS_MEMBER(r3),
    JS_MEMBER(r4), JS_MEMBER(r5), JS_MEMBER(r6), JS_MEMBER(r7),
    JS_MEMBER(r8), JS_MEMBER(r9), JS_MEMBER(r10), JS_MEMBER(r11),
    JS_MEMBER(r12), JS_MEMBER(sp), JS_MEMBER(lr), JS_MEMBER(pc),
    JS_MEMBER(cpsr)
  );
  
#elif defined(QBDI_ARCH_X86)
  // x86 32-bit registers
  uint32_t eax, ebx, ecx, edx, esi, edi, ebp, esp, eip, eflags;
  
  JS_OBJECT(
    JS_MEMBER(eax), JS_MEMBER(ebx), JS_MEMBER(ecx), JS_MEMBER(edx),
    JS_MEMBER(esi), JS_MEMBER(edi), JS_MEMBER(ebp), JS_MEMBER(esp),
    JS_MEMBER(eip), JS_MEMBER(eflags)
  );
  
#else
  // fallback for unknown architectures
  uint64_t unknown_register_data[32];
  
  JS_OBJECT(JS_MEMBER(unknown_register_data));
#endif
};

struct stack_info {
  uint64_t stack_pointer;
  uint64_t return_address;
  std::vector<uint64_t> stack_values;

  JS_OBJECT(JS_MEMBER(stack_pointer), JS_MEMBER(return_address), JS_MEMBER(stack_values));
};

struct transfer_entry {
  transfer_type type;
  uint64_t source_address;
  uint64_t target_address;
  uint64_t timestamp;
  uint64_t instruction_count;
  register_state registers;
  stack_info stack;
  std::string source_module;
  std::string target_module;

  JS_OBJECT(
    JS_MEMBER(type), JS_MEMBER(source_address), JS_MEMBER(target_address),
    JS_MEMBER(timestamp), JS_MEMBER(instruction_count), JS_MEMBER(registers),
    JS_MEMBER(stack), JS_MEMBER(source_module), JS_MEMBER(target_module)
  );
};

struct transfer_stats {
  uint64_t total_calls;
  uint64_t total_returns;
  uint64_t unique_call_targets;
  uint64_t unique_return_sources;
  uint64_t max_call_depth;
  uint64_t current_call_depth;

  JS_OBJECT(
    JS_MEMBER(total_calls), JS_MEMBER(total_returns), JS_MEMBER(unique_call_targets),
    JS_MEMBER(unique_return_sources), JS_MEMBER(max_call_depth), JS_MEMBER(current_call_depth)
  );
};

struct w1xfer_report {
  transfer_stats stats;
  std::vector<transfer_entry> trace;

  JS_OBJECT(JS_MEMBER(stats), JS_MEMBER(trace));
};

class transfer_collector {
public:
  explicit transfer_collector(uint64_t max_entries, bool log_registers, bool log_stack_info, bool log_call_targets);

  void initialize_module_tracking();

  void record_call(uint64_t source_addr, uint64_t target_addr, QBDI::VMInstanceRef vm, 
                   const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr);
  void record_return(uint64_t source_addr, uint64_t target_addr, QBDI::VMInstanceRef vm, 
                     const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr);

  w1xfer_report build_report() const;

  const transfer_stats& get_stats() const { return stats_; }
  size_t get_trace_size() const { return trace_.size(); }
  uint64_t get_instruction_count() const { return instruction_count_; }
  
  std::string get_module_name(uint64_t address) const;

private:
  transfer_stats stats_;
  std::vector<transfer_entry> trace_;
  uint64_t max_entries_;
  uint64_t instruction_count_;
  bool log_registers_;
  bool log_stack_info_;
  bool log_call_targets_;
  bool trace_overflow_;
  w1::util::module_scanner scanner_;
  w1::util::module_range_index index_;
  bool modules_initialized_;

  register_state capture_registers(QBDI::GPRState* gpr) const;
  stack_info capture_stack_info(QBDI::VMInstanceRef vm, QBDI::GPRState* gpr) const;
  uint64_t get_timestamp() const;
  void update_call_depth(transfer_type type);
};

} // namespace w1xfer

// custom serialization for transfer_type enum outside namespace
namespace JS {
template<>
struct TypeHandler<w1xfer::transfer_type> {
  static inline void from(const w1xfer::transfer_type& from_type, Token& token, Serializer& serializer) {
    std::string type_str = (from_type == w1xfer::transfer_type::CALL) ? "call" : "return";
    TypeHandler<std::string>::from(type_str, token, serializer);
  }
  static inline void to(w1xfer::transfer_type& to_type, ParseContext& context) {
    std::string type_str;
    TypeHandler<std::string>::to(type_str, context);
    to_type = (type_str == "call") ? w1xfer::transfer_type::CALL : w1xfer::transfer_type::RETURN;
  }
};
}