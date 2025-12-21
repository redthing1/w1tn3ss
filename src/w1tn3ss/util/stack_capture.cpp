#include "w1tn3ss/util/stack_capture.hpp"

#include <algorithm>
#include <cstring>

namespace w1::util {

stack_info stack_capturer::capture(
    const memory_reader& memory, const register_state& regs, const capture_options& options
) {
  memory_reader_fn reader = [&memory](uint64_t addr, void* buffer, size_t size) -> bool {
    auto bytes = memory.read_bytes(addr, size);
    if (!bytes || bytes->size() != size) {
      return false;
    }
    std::memcpy(buffer, bytes->data(), size);
    return true;
  };

  return capture_with_reader(regs, reader, options);
}

stack_info stack_capturer::capture_with_reader(
    const register_state& regs, memory_reader_fn reader, const capture_options& options
) {
  stack_info info;

  info.stack_pointer = regs.get_stack_pointer();
  info.frame_pointer = regs.get_frame_pointer();

  if (info.stack_pointer == 0) {
    return info;
  }

  info.values.reserve(options.num_values);

  for (size_t i = 0; i < options.num_values; ++i) {
    stack_info::stack_entry entry;
    entry.offset = options.start_offset + static_cast<int64_t>(i * options.value_spacing);

    uint64_t addr = info.stack_pointer;
    if (entry.offset >= 0) {
      addr += static_cast<uint64_t>(entry.offset);
    } else {
      uint64_t delta = static_cast<uint64_t>(-entry.offset);
      if (delta > addr) {
        entry.is_valid = false;
        entry.value = 0;
        info.values.push_back(entry);
        continue;
      }
      addr -= delta;
    }
    entry.is_valid = read_stack_value(reader, addr, entry.value);

    info.values.push_back(entry);
  }

  if (!info.values.empty() && info.values[0].offset == 0 && info.values[0].is_valid) {
    info.return_address = info.values[0].value;
  } else {
    read_stack_value(reader, info.stack_pointer, info.return_address);
  }

  if (options.analyze_frame) {
    switch (regs.get_architecture()) {
    case register_state::architecture::x86_64:
      analyze_x86_64_frame(info, regs, reader);
      break;
    case register_state::architecture::aarch64:
      analyze_aarch64_frame(info, regs, reader);
      break;
    case register_state::architecture::arm32:
      analyze_arm32_frame(info, regs, reader);
      break;
    case register_state::architecture::x86:
      analyze_x86_frame(info, regs, reader);
      break;
    default:
      break;
    }
  }

  return info;
}

void stack_capturer::analyze_x86_64_frame(stack_info& info, const register_state&, memory_reader_fn& reader) {
  if (info.frame_pointer != 0 && info.frame_pointer > info.stack_pointer) {
    info.has_frame_pointer = true;
    info.estimated_frame_size = info.frame_pointer - info.stack_pointer;

    uint64_t saved_rbp = 0;
    uint64_t saved_rip = 0;

    if (read_stack_value(reader, info.frame_pointer, saved_rbp) &&
        read_stack_value(reader, info.frame_pointer + 8, saved_rip)) {
      if (info.return_address == 0) {
        info.return_address = saved_rip;
      }
    }
  }
}

void stack_capturer::analyze_aarch64_frame(stack_info& info, const register_state& regs, memory_reader_fn& reader) {
  if (info.frame_pointer != 0 && info.frame_pointer >= info.stack_pointer) {
    info.has_frame_pointer = true;
    info.estimated_frame_size = info.frame_pointer - info.stack_pointer + 16;

    uint64_t saved_fp = 0;
    uint64_t saved_lr = 0;

    if (read_stack_value(reader, info.frame_pointer - 16, saved_fp) &&
        read_stack_value(reader, info.frame_pointer - 8, saved_lr)) {
      if (info.return_address == 0) {
        info.return_address = saved_lr;
      }
    }
  }

  uint64_t lr_value = 0;
  if (info.return_address == 0 && regs.get_register("lr", lr_value)) {
    info.return_address = lr_value;
  }
}

void stack_capturer::analyze_arm32_frame(stack_info& info, const register_state& regs, memory_reader_fn& reader) {
  if (info.frame_pointer != 0 && info.frame_pointer >= info.stack_pointer) {
    info.has_frame_pointer = true;
    info.estimated_frame_size = info.frame_pointer - info.stack_pointer + 8;

    uint64_t saved_fp = 0;
    uint64_t saved_lr = 0;

    if (read_stack_value(reader, info.frame_pointer - 8, saved_fp) &&
        read_stack_value(reader, info.frame_pointer - 4, saved_lr)) {
      if (info.return_address == 0) {
        info.return_address = saved_lr & 0xFFFFFFFF;
      }
    }
  }

  uint64_t lr_value = 0;
  if (info.return_address == 0 && regs.get_register("lr", lr_value)) {
    info.return_address = lr_value & 0xFFFFFFFF;
  }
}

void stack_capturer::analyze_x86_frame(stack_info& info, const register_state&, memory_reader_fn& reader) {
  if (info.frame_pointer != 0 && info.frame_pointer > info.stack_pointer) {
    info.has_frame_pointer = true;
    info.estimated_frame_size = info.frame_pointer - info.stack_pointer;

    uint64_t saved_ebp = 0;
    uint64_t saved_eip = 0;

    if (read_stack_value(reader, info.frame_pointer, saved_ebp) &&
        read_stack_value(reader, info.frame_pointer + 4, saved_eip)) {
      if (info.return_address == 0) {
        info.return_address = saved_eip & 0xFFFFFFFF;
      }
    }
  }
}

bool stack_capturer::read_stack_value(memory_reader_fn& reader, uint64_t addr, uint64_t& value) {
  constexpr size_t ptr_size = 8;
  uint8_t buffer[ptr_size] = {0};

  if (reader(addr, buffer, ptr_size)) {
    value = 0;
    for (size_t i = 0; i < ptr_size; ++i) {
      value |= static_cast<uint64_t>(buffer[i]) << (i * 8);
    }
    return true;
  }

  value = 0;
  return false;
}

std::vector<stack_walker::frame> stack_walker::walk(
    const memory_reader& memory, const register_state& regs, size_t max_frames
) {
  std::vector<frame> frames;
  frames.reserve(max_frames);

  stack_capturer::memory_reader_fn reader = [&memory](uint64_t addr, void* buffer, size_t size) -> bool {
    auto bytes = memory.read_bytes(addr, size);
    if (!bytes || bytes->size() != size) {
      return false;
    }
    std::memcpy(buffer, bytes->data(), size);
    return true;
  };

  frame current;
  current.sp = regs.get_stack_pointer();
  current.fp = regs.get_frame_pointer();

  if (current.sp != 0) {
    uint64_t ret_addr = 0;
    if (stack_capturer::read_stack_value(reader, current.sp, ret_addr)) {
      current.return_address = ret_addr;
    }

    current.frame_size = (current.fp > current.sp) ? (current.fp - current.sp) : 0;
    frames.push_back(current);
  }

  return frames;
}

} // namespace w1::util
