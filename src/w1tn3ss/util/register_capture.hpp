#pragma once

#include <QBDI.h>
#include <cstdint>
#include <vector>
#include <string>
#include <unordered_map>

namespace w1::util {

/**
 * @brief Architecture-independent register state representation
 *
 * This structure provides a unified way to capture and access register values
 * across different architectures without architecture-specific code in users.
 */
class register_state {
public:
  // architecture type for runtime queries
  enum class architecture { X86_64, AARCH64, ARM32, X86, UNKNOWN };

  // get current architecture
  architecture get_architecture() const { return arch_; }

  // generic register access by name
  bool get_register(const std::string& name, uint64_t& value) const;

  // common register accessors (work across architectures)
  uint64_t get_stack_pointer() const;
  uint64_t get_instruction_pointer() const;
  uint64_t get_frame_pointer() const;
  uint64_t get_return_value() const;

  // get first N argument registers (architecture-aware)
  std::vector<uint64_t> get_argument_registers(size_t count) const;

  // get all register names for current architecture
  std::vector<std::string> get_register_names() const;

  // get all registers as name->value map
  std::unordered_map<std::string, uint64_t> get_all_registers() const;

  // internal: populated by register_capturer
  friend class register_capturer;

private:
  architecture arch_ = architecture::UNKNOWN;
  std::unordered_map<std::string, uint64_t> registers_;

  // architecture-specific mappings
  static const std::unordered_map<std::string, std::string> common_mappings_;
};

/**
 * @brief Captures register state from QBDI GPRState
 *
 * This class provides a clean abstraction for capturing register state
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