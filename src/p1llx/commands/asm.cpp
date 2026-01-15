#include "asm.hpp"

#include <iostream>

#include <redlog.hpp>

#include "p1ll/asmr/asmr.hpp"
#include "p1ll/utils/hex_utils.hpp"
#include "platform_utils.hpp"

namespace p1llx::commands {

int asm_command(const asm_request& request) {
  auto log = redlog::get_logger("p1llx.asm");

  if (request.text.empty()) {
    log.err("assembly text required");
    std::cerr << "error: assembly text is required" << std::endl;
    return 1;
  }

  auto platform = resolve_platform(request.platform);
  if (!platform.ok()) {
    log.err("invalid platform override", redlog::field("error", platform.status.message));
    std::cerr << "error: invalid platform override" << std::endl;
    return 1;
  }

  auto ctx = p1ll::asmr::context::for_platform(platform.value);
  if (!ctx.ok()) {
    log.err("failed to initialize assembler", redlog::field("error", ctx.status.message));
    std::cerr << "error: failed to initialize assembler" << std::endl;
    return 1;
  }

  uint64_t address = request.has_address ? request.address : 0;
  auto assembled = ctx.value.assemble(request.text, address);
  if (!assembled.ok()) {
    log.err("assembly failed", redlog::field("error", assembled.status.message));
    std::cerr << "error: assembly failed" << std::endl;
    return 1;
  }

  std::cout << p1ll::utils::format_bytes(assembled.value) << std::endl;
  return 0;
}

} // namespace p1llx::commands
