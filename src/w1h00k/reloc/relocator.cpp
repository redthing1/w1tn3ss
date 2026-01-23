#include "w1h00k/reloc/relocator.hpp"

#include "w1asmr/asmr.hpp"
#include "w1asmr/result.hpp"
#include "w1base/arch_spec.hpp"
#include "w1h00k/reloc/arm64.hpp"
#include "w1h00k/reloc/common.hpp"
#include "w1h00k/reloc/x86.hpp"

namespace w1::h00k::reloc {

reloc_result relocate(const void* target, size_t min_patch_size) {
  return relocate(target, min_patch_size, 0, w1::arch::detect_host_arch_spec());
}

reloc_result relocate(const void* target, size_t min_patch_size, uint64_t trampoline_address) {
  return relocate(target, min_patch_size, trampoline_address, w1::arch::detect_host_arch_spec());
}

reloc_result relocate(const void* target, size_t min_patch_size, uint64_t trampoline_address,
                      const w1::arch::arch_spec& arch) {
  auto fail = [](reloc_error error) {
    reloc_result out{};
    out.error = error;
    return out;
  };

  if (!target) {
    return fail(reloc_error::invalid_target);
  }
  if (min_patch_size == 0 || min_patch_size > detail::kMaxPatchBytes) {
    return fail(reloc_error::invalid_request);
  }

  auto disasm = w1::asmr::disasm_context::for_arch(arch);
  if (!disasm.ok()) {
    if (disasm.status_info.code == w1::asmr::error_code::unsupported) {
      return fail(reloc_error::unsupported_arch);
    }
    return fail(reloc_error::decode_failed);
  }

  switch (arch.arch_mode) {
    case w1::arch::mode::x86_32:
    case w1::arch::mode::x86_64:
      return detail::relocate_x86(disasm.value, target, min_patch_size, trampoline_address);
    case w1::arch::mode::aarch64:
      return detail::relocate_arm64(disasm.value, target, min_patch_size, trampoline_address);
    default:
      return fail(reloc_error::unsupported_arch);
  }
}

size_t max_trampoline_size(size_t min_patch_size, const w1::arch::arch_spec& arch) {
  if (min_patch_size == 0 || min_patch_size > detail::kMaxPatchBytes) {
    return 0;
  }

  constexpr size_t kX86MinRelocInsn = 2;
  constexpr size_t kX86MaxStubX64 = 16;
  constexpr size_t kX86MaxStubX86 = 12;
  constexpr size_t kArm64InsnBytes = 4;
  constexpr size_t kArm64MaxStub = 20;

  const size_t patch_bytes = detail::kMaxPatchBytes;
  auto ceil_div = [](size_t num, size_t den) {
    return (num + den - 1) / den;
  };

  switch (arch.arch_mode) {
    case w1::arch::mode::x86_32: {
      const size_t max_insns = ceil_div(patch_bytes, kX86MinRelocInsn);
      return max_insns * kX86MaxStubX86;
    }
    case w1::arch::mode::x86_64: {
      const size_t max_insns = ceil_div(patch_bytes, kX86MinRelocInsn);
      return max_insns * kX86MaxStubX64;
    }
    case w1::arch::mode::aarch64: {
      const size_t max_insns = ceil_div(patch_bytes, kArm64InsnBytes);
      return max_insns * kArm64MaxStub;
    }
    default:
      break;
  }

  return 0;
}

const char* to_string(reloc_error error) {
  switch (error) {
    case reloc_error::ok:
      return "ok";
    case reloc_error::invalid_target:
      return "invalid_target";
    case reloc_error::invalid_request:
      return "invalid_request";
    case reloc_error::unsupported_arch:
      return "unsupported_arch";
    case reloc_error::decode_failed:
      return "decode_failed";
    case reloc_error::insufficient_bytes:
      return "insufficient_bytes";
    case reloc_error::missing_trampoline:
      return "missing_trampoline";
    case reloc_error::unsupported_instruction:
      return "unsupported_instruction";
    case reloc_error::out_of_range:
      return "out_of_range";
  }
  return "unknown";
}

} // namespace w1::h00k::reloc
