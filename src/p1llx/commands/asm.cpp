#include "asm.hpp"

#include <iostream>

#include <redlog.hpp>

#include "p1ll/utils/hex_utils.hpp"
#include "w1asmr/asmr.hpp"

namespace p1llx::commands {

namespace {

w1::asmr::result<w1::asmr::arch_spec> resolve_arch(const std::string& arch_override) {
  if (arch_override.empty()) {
    return w1::asmr::detect_host_arch_spec();
  }
  return w1::asmr::parse_arch_spec(arch_override);
}

} // namespace

int asm_command(const asm_request& request) {
  auto log = redlog::get_logger("p1llx.asm");

  if (request.text.empty()) {
    log.err("assembly text required");
    std::cerr << "error: assembly text is required" << std::endl;
    return 1;
  }

  auto arch_value = resolve_arch(request.arch);
  if (!arch_value.ok()) {
    log.err("invalid arch override", redlog::field("error", arch_value.status_info.message));
    std::cerr << "error: invalid arch override" << std::endl;
    return 1;
  }

  auto ctx = w1::asmr::asm_context::for_arch(arch_value.value);
  if (!ctx.ok()) {
    log.err("failed to initialize assembler", redlog::field("error", ctx.status_info.message));
    std::cerr << "error: failed to initialize assembler" << std::endl;
    return 1;
  }

  uint64_t address = request.has_address ? request.address : 0;
  auto assembled = ctx.value.assemble(request.text, address);
  if (!assembled.ok()) {
    log.err("assembly failed", redlog::field("error", assembled.status_info.message));
    std::cerr << "error: assembly failed" << std::endl;
    return 1;
  }

  std::cout << p1ll::utils::format_bytes(assembled.value) << std::endl;
  return 0;
}

} // namespace p1llx::commands
