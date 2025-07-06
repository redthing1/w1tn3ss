#include "stack_capture.hpp"
#include "safe_memory.hpp"
#include <cstring>
#include <algorithm>

namespace w1::util {

stack_info stack_capturer::capture(QBDI::VMInstanceRef vm, const register_state& regs, const capture_options& options) {
  // create memory reader lambda that uses safe_memory
  memory_reader reader = [vm](uint64_t addr, void* buffer, size_t size) -> bool {
    try {
      // use safe_memory to read buffer
      auto result = safe_memory::read_buffer(vm, addr, size, size);
      if (result.has_value() && result->bytes_read == size) {
        std::memcpy(buffer, result->data.data(), size);
        return true;
      }
      return false;
    } catch (...) {
      return false;
    }
  };

  return capture_with_reader(regs, reader, options);
}

stack_info stack_capturer::capture_with_reader(
    const register_state& regs, memory_reader reader, const capture_options& options
) {
  stack_info info;

  // get basic register values
  info.stack_pointer = regs.get_stack_pointer();
  info.frame_pointer = regs.get_frame_pointer();

  if (info.stack_pointer == 0) {
    return info; // invalid stack pointer
  }

  // capture stack values around the stack pointer
  info.values.reserve(options.num_values);

  for (size_t i = 0; i < options.num_values; ++i) {
    stack_info::stack_entry entry;
    entry.offset = options.start_offset + (i * options.value_spacing);

    uint64_t addr = info.stack_pointer + entry.offset;
    entry.is_valid = read_stack_value(reader, addr, entry.value);

    info.values.push_back(entry);
  }

  // read return address (typically at [rsp] on x64 call)
  if (!info.values.empty() && info.values[0].offset == 0 && info.values[0].is_valid) {
    info.return_address = info.values[0].value;
  } else {
    // try to read at sp+0 if not already captured
    read_stack_value(reader, info.stack_pointer, info.return_address);
  }

  // perform architecture-specific frame analysis if requested
  if (options.analyze_frame) {
    switch (regs.get_architecture()) {
    case register_state::architecture::X86_64:
      analyze_x86_64_frame(info, regs, reader);
      break;
    case register_state::architecture::AARCH64:
      analyze_aarch64_frame(info, regs, reader);
      break;
    case register_state::architecture::ARM32:
      analyze_arm32_frame(info, regs, reader);
      break;
    case register_state::architecture::X86:
      analyze_x86_frame(info, regs, reader);
      break;
    default:
      break;
    }
  }

  return info;
}

void stack_capturer::analyze_x86_64_frame(stack_info& info, const register_state& regs, memory_reader& reader) {
  // x86_64 typically uses rbp as frame pointer in debug builds
  if (info.frame_pointer != 0 && info.frame_pointer > info.stack_pointer) {
    info.has_frame_pointer = true;
    info.estimated_frame_size = info.frame_pointer - info.stack_pointer;

    // read saved rbp and return address from frame
    uint64_t saved_rbp = 0;
    uint64_t saved_rip = 0;

    if (read_stack_value(reader, info.frame_pointer, saved_rbp) &&
        read_stack_value(reader, info.frame_pointer + 8, saved_rip)) {
      // we have a valid frame
      if (info.return_address == 0) {
        info.return_address = saved_rip;
      }
    }
  }

  // check for red zone usage (128 bytes below rsp on x64 system v)
  // this is just informational - we don't capture red zone by default
}

void stack_capturer::analyze_aarch64_frame(stack_info& info, const register_state& regs, memory_reader& reader) {
  // aarch64 uses x29 (fp) and x30 (lr) for frame management
  if (info.frame_pointer != 0 && info.frame_pointer >= info.stack_pointer) {
    info.has_frame_pointer = true;
    info.estimated_frame_size = info.frame_pointer - info.stack_pointer + 16; // fp/lr pair

    // on aarch64, fp and lr are typically stored as a pair at [fp-16]
    uint64_t saved_fp = 0;
    uint64_t saved_lr = 0;

    if (read_stack_value(reader, info.frame_pointer - 16, saved_fp) &&
        read_stack_value(reader, info.frame_pointer - 8, saved_lr)) {
      if (info.return_address == 0) {
        info.return_address = saved_lr;
      }
    }
  }

  // check if lr register has return address
  uint64_t lr_value = 0;
  if (info.return_address == 0 && regs.get_register("lr", lr_value)) {
    info.return_address = lr_value;
  }
}

void stack_capturer::analyze_arm32_frame(stack_info& info, const register_state& regs, memory_reader& reader) {
  // arm32 frame analysis similar to aarch64 but 32-bit
  if (info.frame_pointer != 0 && info.frame_pointer >= info.stack_pointer) {
    info.has_frame_pointer = true;
    info.estimated_frame_size = info.frame_pointer - info.stack_pointer + 8;

    // read saved registers from frame
    uint64_t saved_fp = 0;
    uint64_t saved_lr = 0;

    if (read_stack_value(reader, info.frame_pointer - 8, saved_fp) &&
        read_stack_value(reader, info.frame_pointer - 4, saved_lr)) {
      if (info.return_address == 0) {
        info.return_address = saved_lr & 0xFFFFFFFF; // 32-bit
      }
    }
  }

  // check lr register
  uint64_t lr_value = 0;
  if (info.return_address == 0 && regs.get_register("lr", lr_value)) {
    info.return_address = lr_value & 0xFFFFFFFF;
  }
}

void stack_capturer::analyze_x86_frame(stack_info& info, const register_state& regs, memory_reader& reader) {
  // x86 32-bit frame analysis
  if (info.frame_pointer != 0 && info.frame_pointer > info.stack_pointer) {
    info.has_frame_pointer = true;
    info.estimated_frame_size = info.frame_pointer - info.stack_pointer;

    // standard x86 frame: push ebp; mov ebp, esp
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

bool stack_capturer::read_stack_value(memory_reader& reader, uint64_t addr, uint64_t& value) {
  // determine size based on architecture (could be passed in, but 8 bytes is safe)
  constexpr size_t ptr_size = 8;
  uint8_t buffer[ptr_size] = {0};

  if (reader(addr, buffer, ptr_size)) {
    // little-endian assumption (true for all supported architectures)
    value = 0;
    for (size_t i = 0; i < ptr_size; ++i) {
      value |= static_cast<uint64_t>(buffer[i]) << (i * 8);
    }
    return true;
  }

  value = 0;
  return false;
}

// basic stack walker implementation
std::vector<stack_walker::frame> stack_walker::walk(
    QBDI::VMInstanceRef vm, const register_state& regs, size_t max_frames
) {
  std::vector<frame> frames;
  frames.reserve(max_frames);

  // create memory reader
  stack_capturer::memory_reader reader = [vm](uint64_t addr, void* buffer, size_t size) -> bool {
    try {
      // use safe_memory to read buffer
      auto result = safe_memory::read_buffer(vm, addr, size, size);
      if (result.has_value() && result->bytes_read == size) {
        std::memcpy(buffer, result->data.data(), size);
        return true;
      }
      return false;
    } catch (...) {
      return false;
    }
  };

  // start with current frame
  frame current;
  current.sp = regs.get_stack_pointer();
  current.fp = regs.get_frame_pointer();

  // architecture-specific unwinding would go here
  // for now, just return current frame
  if (current.sp != 0) {
    // read return address
    uint64_t ret_addr = 0;
    if (stack_capturer::read_stack_value(reader, current.sp, ret_addr)) {
      current.return_address = ret_addr;
    }

    current.frame_size = (current.fp > current.sp) ? (current.fp - current.sp) : 0;
    frames.push_back(current);
  }

  // full unwinding implementation would follow frame pointers
  // this is a placeholder for future enhancement

  return frames;
}

} // namespace w1::util