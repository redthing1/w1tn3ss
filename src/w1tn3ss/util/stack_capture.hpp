#pragma once

#include <QBDI.h>
#include <vector>
#include <cstdint>
#include <functional>
#include "register_capture.hpp"

namespace w1::util {

/**
 * @brief Captured stack information
 */
struct stack_info {
  uint64_t stack_pointer = 0;
  uint64_t frame_pointer = 0;
  uint64_t return_address = 0;

  // stack values at various offsets
  struct stack_entry {
    int64_t offset; // offset from stack pointer (can be negative)
    uint64_t value; // value at that location
    bool is_valid;  // whether read was successful
  };

  std::vector<stack_entry> values;

  // additional analysis results
  size_t estimated_frame_size = 0;
  bool has_frame_pointer = false;
};

/**
 * @brief Stack capture and analysis utility
 *
 * Provides safe stack reading and analysis across architectures
 */
class stack_capturer {
public:
  struct capture_options {
    size_t num_values = 8;     // number of stack values to capture
    int64_t start_offset = -8; // where to start capturing (relative to SP)
    size_t value_spacing = 8;  // spacing between captured values
    bool analyze_frame = true; // whether to analyze frame structure
    bool capture_args = true;  // capture potential arguments on stack

    capture_options() : num_values(8), start_offset(-8), value_spacing(8), analyze_frame(true), capture_args(true) {}
  };

  // memory reader function type
  using memory_reader = std::function<bool(uint64_t addr, void* buffer, size_t size)>;

  /**
   * capture stack information
   * @param vm QBDI VM instance for memory access
   * @param regs register state (from register_capturer)
   * @param options capture options
   */
  static stack_info capture(QBDI::VMInstanceRef vm, const register_state& regs, const capture_options& options = {});

  /**
   * capture with custom memory reader (for testing or special cases)
   */
  static stack_info capture_with_reader(
      const register_state& regs, memory_reader reader, const capture_options& options = {}
  );

  // helper to read stack values safely (public for stack_walker)
  static bool read_stack_value(memory_reader& reader, uint64_t addr, uint64_t& value);

private:
  // architecture-specific stack analysis
  static void analyze_x86_64_frame(stack_info& info, const register_state& regs, memory_reader& reader);
  static void analyze_aarch64_frame(stack_info& info, const register_state& regs, memory_reader& reader);
  static void analyze_arm32_frame(stack_info& info, const register_state& regs, memory_reader& reader);
  static void analyze_x86_frame(stack_info& info, const register_state& regs, memory_reader& reader);
};

/**
 * @brief Stack walker for unwinding call stacks
 *
 * More advanced stack walking functionality (future extension)
 */
class stack_walker {
public:
  struct frame {
    uint64_t sp;
    uint64_t fp;
    uint64_t return_address;
    size_t frame_size;
  };

  // walk stack frames up to max_frames
  static std::vector<frame> walk(QBDI::VMInstanceRef vm, const register_state& regs, size_t max_frames = 32);
};

} // namespace w1::util