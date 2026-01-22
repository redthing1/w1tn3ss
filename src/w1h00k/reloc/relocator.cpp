#include "w1h00k/reloc/relocator.hpp"

#include "w1asmr/asmr.hpp"
#include "w1asmr/result.hpp"
#include "w1base/arch_spec.hpp"
#include "w1h00k/reloc/reloc_arm64.hpp"
#include "w1h00k/reloc/reloc_common.hpp"
#include "w1h00k/reloc/reloc_x86.hpp"

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

} // namespace w1::h00k::reloc
