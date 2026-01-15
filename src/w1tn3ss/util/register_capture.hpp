#pragma once

#include <QBDI.h>

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace w1::util {

class register_state {
public:
  enum class architecture { x86_64, aarch64, arm32, x86, unknown };

  architecture get_architecture() const { return arch_; }

  bool get_register(const std::string& name, uint64_t& value) const;
  uint64_t get_stack_pointer() const;
  uint64_t get_instruction_pointer() const;
  uint64_t get_frame_pointer() const;

  std::vector<std::string> get_register_names() const;
  std::unordered_map<std::string, uint64_t> get_all_registers() const;

  // direct const access used for delta calculations to avoid copies
  const std::unordered_map<std::string, uint64_t>& get_register_map() const { return registers_; }
  friend class register_capturer;

private:
  architecture arch_ = architecture::unknown;
  std::unordered_map<std::string, uint64_t> registers_;
};

class register_capturer {
public:
  static register_state capture(const QBDI::GPRState* gpr);

private:
  static void capture_x86_64(register_state& state, const QBDI::GPRState* gpr);
  static void capture_aarch64(register_state& state, const QBDI::GPRState* gpr);
  static void capture_arm32(register_state& state, const QBDI::GPRState* gpr);
  static void capture_x86(register_state& state, const QBDI::GPRState* gpr);
};

} // namespace w1::util
