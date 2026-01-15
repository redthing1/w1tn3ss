#include "disasm.hpp"

#include <cctype>
#include <iostream>
#include <string>
#include <vector>

#include <redlog.hpp>

#include "p1ll/asmr/asmr.hpp"
#include "p1ll/utils/hex_utils.hpp"
#include "platform_utils.hpp"

namespace p1llx::commands {

namespace {

bool parse_hex_bytes(const std::string& input, std::vector<uint8_t>& output, std::string& error) {
  std::string clean;
  clean.reserve(input.size());

  for (char c : input) {
    if (std::isspace(static_cast<unsigned char>(c))) {
      continue;
    }
    if (c == '?') {
      error = "wildcards are not supported for disasm";
      return false;
    }
    clean.push_back(c);
  }

  if (clean.empty()) {
    error = "hex input is empty";
    return false;
  }

  if (clean.size() % 2 != 0) {
    error = "hex input must have an even number of digits";
    return false;
  }

  output.clear();
  output.reserve(clean.size() / 2);
  for (size_t i = 0; i < clean.size(); i += 2) {
    char hi = clean[i];
    char lo = clean[i + 1];
    if (!p1ll::utils::is_hex_digit(hi) || !p1ll::utils::is_hex_digit(lo)) {
      error = "hex input contains non-hex characters";
      return false;
    }
    uint8_t byte = static_cast<uint8_t>((p1ll::utils::parse_hex_digit(hi) << 4) | p1ll::utils::parse_hex_digit(lo));
    output.push_back(byte);
  }

  return true;
}

} // namespace

int disasm_command(const disasm_request& request) {
  auto log = redlog::get_logger("p1llx.disasm");

  if (request.bytes.empty()) {
    log.err("hex bytes required");
    std::cerr << "error: hex bytes are required" << std::endl;
    return 1;
  }

  std::vector<uint8_t> bytes;
  std::string parse_error;
  if (!parse_hex_bytes(request.bytes, bytes, parse_error)) {
    log.err("invalid hex bytes", redlog::field("error", parse_error));
    std::cerr << "error: invalid hex bytes" << std::endl;
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
    log.err("failed to initialize disassembler", redlog::field("error", ctx.status.message));
    std::cerr << "error: failed to initialize disassembler" << std::endl;
    return 1;
  }

  uint64_t address = request.has_address ? request.address : 0;
  auto disassembled = ctx.value.disassemble(bytes, address);
  if (!disassembled.ok()) {
    log.err("disassembly failed", redlog::field("error", disassembled.status.message));
    std::cerr << "error: disassembly failed" << std::endl;
    return 1;
  }

  for (const auto& inst : disassembled.value) {
    std::cout << p1ll::utils::format_address(inst.address) << ": " << p1ll::utils::format_bytes(inst.bytes);
    if (!inst.mnemonic.empty()) {
      std::cout << "  " << inst.mnemonic;
      if (!inst.operands.empty()) {
        std::cout << " " << inst.operands;
      }
    }
    std::cout << "\n";
  }

  return 0;
}

} // namespace p1llx::commands
