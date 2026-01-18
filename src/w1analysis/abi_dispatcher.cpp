#include "w1analysis/abi_dispatcher.hpp"

namespace w1::analysis {
namespace {

#if defined(QBDI_ARCH_X86_64)
constexpr size_t word_size_bytes = 8;
#elif defined(QBDI_ARCH_AARCH64)
constexpr size_t word_size_bytes = 8;
#elif defined(QBDI_ARCH_X86)
constexpr size_t word_size_bytes = 4;
#else
constexpr size_t word_size_bytes = sizeof(uint64_t);
#endif

} // namespace

abi_dispatcher::abi_dispatcher() { config_.kind = detect_native_kind(); }

abi_dispatcher::abi_dispatcher(abi_dispatcher_config config) : config_(config) {
  if (config_.kind == abi_kind::unknown) {
    config_.kind = detect_native_kind();
  }
}

std::vector<call_argument> abi_dispatcher::extract_arguments(
    const util::memory_reader& memory, const QBDI::GPRState* gpr, size_t argument_count
) const {
  std::vector<call_argument> args;
  args.reserve(argument_count);

  if (!gpr) {
    return args;
  }

  for (size_t index = 0; index < argument_count; ++index) {
    call_argument arg{};

    switch (config_.kind) {
#if defined(QBDI_ARCH_X86_64)
    case abi_kind::system_v_amd64: {
      constexpr size_t reg_count = 6;
      if (index < reg_count) {
        const uint64_t values[] = {gpr->rdi, gpr->rsi, gpr->rdx, gpr->rcx, gpr->r8, gpr->r9};
        arg.raw_value = values[index];
        arg.from_register = true;
        arg.is_valid = true;
      } else if (config_.enable_stack_reads) {
        uint64_t stack_address = gpr->rsp + word_size_bytes + (index - reg_count) * word_size_bytes;
        if (auto value = read_stack_value(memory, stack_address, word_size_bytes)) {
          arg.raw_value = *value;
          arg.is_valid = true;
        }
      }
      break;
    }
    case abi_kind::windows_amd64: {
      constexpr size_t reg_count = 4;
      if (index < reg_count) {
        const uint64_t values[] = {gpr->rcx, gpr->rdx, gpr->r8, gpr->r9};
        arg.raw_value = values[index];
        arg.from_register = true;
        arg.is_valid = true;
      } else if (config_.enable_stack_reads) {
        uint64_t stack_address = gpr->rsp + 0x28 + (index - reg_count) * word_size_bytes;
        if (auto value = read_stack_value(memory, stack_address, word_size_bytes)) {
          arg.raw_value = *value;
          arg.is_valid = true;
        }
      }
      break;
    }
#endif
#if defined(QBDI_ARCH_AARCH64)
    case abi_kind::aarch64: {
      constexpr size_t reg_count = 8;
      if (index < reg_count) {
        const uint64_t values[] = {gpr->x0, gpr->x1, gpr->x2, gpr->x3, gpr->x4, gpr->x5, gpr->x6, gpr->x7};
        arg.raw_value = values[index];
        arg.from_register = true;
        arg.is_valid = true;
      } else if (config_.enable_stack_reads) {
        uint64_t stack_address = gpr->sp + (index - reg_count) * word_size_bytes;
        if (auto value = read_stack_value(memory, stack_address, word_size_bytes)) {
          arg.raw_value = *value;
          arg.is_valid = true;
        }
      }
      break;
    }
#endif
#if defined(QBDI_ARCH_X86)
    case abi_kind::x86: {
      if (config_.enable_stack_reads) {
        uint64_t stack_address = gpr->esp + word_size_bytes + index * word_size_bytes;
        if (auto value = read_stack_value(memory, stack_address, word_size_bytes)) {
          arg.raw_value = *value;
          arg.is_valid = true;
        }
      }
      break;
    }
#endif
    default:
      break;
    }

    args.push_back(arg);
  }

  return args;
}

uint64_t abi_dispatcher::extract_return_value(const QBDI::GPRState* gpr) const {
  if (!gpr) {
    return 0;
  }

  switch (config_.kind) {
#if defined(QBDI_ARCH_X86_64)
  case abi_kind::system_v_amd64:
  case abi_kind::windows_amd64:
    return gpr->rax;
#endif
#if defined(QBDI_ARCH_AARCH64)
  case abi_kind::aarch64:
    return gpr->x0;
#endif
#if defined(QBDI_ARCH_X86)
  case abi_kind::x86:
    return gpr->eax;
#endif
  default:
    return 0;
  }
}

abi_kind abi_dispatcher::detect_native_kind() {
#if defined(_WIN32) && defined(QBDI_ARCH_X86_64)
  return abi_kind::windows_amd64;
#elif defined(QBDI_ARCH_X86_64)
  return abi_kind::system_v_amd64;
#elif defined(QBDI_ARCH_AARCH64)
  return abi_kind::aarch64;
#elif defined(QBDI_ARCH_X86)
  return abi_kind::x86;
#else
  return abi_kind::unknown;
#endif
}

std::optional<uint64_t> abi_dispatcher::read_stack_value(
    const util::memory_reader& memory, uint64_t stack_address, size_t word_size
) const {
  auto bytes = memory.read_bytes(stack_address, word_size);
  if (!bytes || bytes->size() != word_size) {
    return std::nullopt;
  }

  uint64_t value = 0;
  for (size_t i = 0; i < bytes->size(); ++i) {
    value |= static_cast<uint64_t>((*bytes)[i]) << (8 * i);
  }

  return value;
}

} // namespace w1::analysis
