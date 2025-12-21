#pragma once

#include <cstdint>
#include <functional>
#include <vector>

#include "w1tn3ss/util/memory_reader.hpp"
#include "w1tn3ss/util/register_capture.hpp"

namespace w1::util {

struct stack_info {
  uint64_t stack_pointer = 0;
  uint64_t frame_pointer = 0;
  uint64_t return_address = 0;

  struct stack_entry {
    int64_t offset = 0;
    uint64_t value = 0;
    bool is_valid = false;
  };

  std::vector<stack_entry> values;
  size_t estimated_frame_size = 0;
  bool has_frame_pointer = false;
};

class stack_capturer {
public:
  struct capture_options {
    size_t num_values;
    int64_t start_offset;
    size_t value_spacing;
    bool analyze_frame;
    bool capture_args;

    constexpr capture_options(
        size_t num_values_value = 8,
        int64_t start_offset_value = -8,
        size_t value_spacing_value = 8,
        bool analyze_frame_value = true,
        bool capture_args_value = true
    )
        : num_values(num_values_value),
          start_offset(start_offset_value),
          value_spacing(value_spacing_value),
          analyze_frame(analyze_frame_value),
          capture_args(capture_args_value) {}
  };

  using memory_reader_fn = std::function<bool(uint64_t addr, void* buffer, size_t size)>;

  static stack_info capture(
      const memory_reader& memory, const register_state& regs, const capture_options& options = capture_options{}
  );

  static stack_info capture_with_reader(
      const register_state& regs, memory_reader_fn reader, const capture_options& options = capture_options{}
  );

  static bool read_stack_value(memory_reader_fn& reader, uint64_t addr, uint64_t& value);

private:
  static void analyze_x86_64_frame(stack_info& info, const register_state& regs, memory_reader_fn& reader);
  static void analyze_aarch64_frame(stack_info& info, const register_state& regs, memory_reader_fn& reader);
  static void analyze_arm32_frame(stack_info& info, const register_state& regs, memory_reader_fn& reader);
  static void analyze_x86_frame(stack_info& info, const register_state& regs, memory_reader_fn& reader);
};

class stack_walker {
public:
  struct frame {
    uint64_t sp = 0;
    uint64_t fp = 0;
    uint64_t return_address = 0;
    size_t frame_size = 0;
  };

  static std::vector<frame> walk(const memory_reader& memory, const register_state& regs, size_t max_frames = 32);
};

} // namespace w1::util
