#pragma once

#include <QBDI.h>
#include <cstdint>
#include <vector>
#include <string>
#include <unordered_map>

namespace w1::util {

/**
 * @brief full register state capture for debugging and tracing
 *
 * this class captures all cpu registers for debugging, tracing, and analysis.
 * it provides a complete snapshot of the register state at a point in time.
 * 
 * note: this is for full state capture. for efficient access to specific
 * architectural registers (pc, sp), use register_access.hpp instead.
 * for abi-specific operations (arguments, return values), use the calling
 * convention layer.
 */
class register_state {
public:
  // architecture type for runtime queries
  enum class architecture { X86_64, AARCH64, ARM32, X86, UNKNOWN };

  // get current architecture
  architecture get_architecture() const { return arch_; }

  // generic register access by name
  bool get_register(const std::string& name, uint64_t& value) const;

  // architectural register accessors for convenience
  // note: for performance-critical code, use register_access.hpp directly
  uint64_t get_stack_pointer() const;
  uint64_t get_instruction_pointer() const;
  
  // returns the architectural register commonly used as frame pointer
  // note: this is just the register value - actual frame pointer
  // usage and semantics are abi-specific
  uint64_t get_frame_pointer() const;
  
  // get all register names for current architecture
  std::vector<std::string> get_register_names() const;

  // get all registers as name->value map
  std::unordered_map<std::string, uint64_t> get_all_registers() const;

  // internal: populated by register_capturer
  friend class register_capturer;

private:
  architecture arch_ = architecture::UNKNOWN;
  std::unordered_map<std::string, uint64_t> registers_;

};

/**
 * @brief captures register state from qbdi gprstate
 *
 * this class provides a clean abstraction for capturing register state
 * across different architectures, eliminating code duplication.
 */
class register_capturer {
public:
  // capture current register state
  static register_state capture(const QBDI::GPRState* gpr);

  // capture with floating point registers (future extension)
  // static register_state capture_full(const QBDI::GPRState* gpr, const QBDI::FPRState* fpr);

private:
  // architecture-specific capture implementations
  static void capture_x86_64(register_state& state, const QBDI::GPRState* gpr);
  static void capture_aarch64(register_state& state, const QBDI::GPRState* gpr);
  static void capture_arm32(register_state& state, const QBDI::GPRState* gpr);
  static void capture_x86(register_state& state, const QBDI::GPRState* gpr);
};

} // namespace w1::util