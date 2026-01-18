#include "asmr_block_decoder.hpp"

#include "code_source.hpp"

#include <cstddef>
#include <limits>
#include <optional>
#include <vector>

#if defined(WITNESS_ASMR_ENABLED)
#include "w1asmr/asmr.hpp"
#endif

namespace w1replay {

namespace {

#if defined(WITNESS_ASMR_ENABLED)
std::optional<w1::asmr::arch> trace_arch_to_asmr_arch(w1::rewind::trace_arch arch) {
  switch (arch) {
  case w1::rewind::trace_arch::x86:
    return w1::asmr::arch::x86;
  case w1::rewind::trace_arch::x86_64:
    return w1::asmr::arch::x64;
  case w1::rewind::trace_arch::aarch64:
    return w1::asmr::arch::arm64;
  default:
    return std::nullopt;
  }
}
#endif

} // namespace

bool asmr_decoder_available() {
#if defined(WITNESS_ASMR_ENABLED) && defined(WITNESS_LIEF_ENABLED)
  return true;
#else
  return false;
#endif
}

asmr_block_decoder::~asmr_block_decoder() = default;

bool asmr_block_decoder::decode_block(
    const w1::rewind::replay_context& context,
    uint64_t address,
    uint32_t size,
    w1::rewind::replay_decoded_block& out,
    std::string& error
) {
#if !defined(WITNESS_ASMR_ENABLED)
  (void)context;
  (void)address;
  (void)size;
  (void)out;
  error = "asmr decoder unavailable (build with WITNESS_ASMR=ON)";
  return false;
#elif !defined(WITNESS_LIEF_ENABLED)
  (void)context;
  (void)address;
  (void)size;
  (void)out;
  error = "asmr decoder unavailable (build with WITNESS_LIEF=ON)";
  return false;
#else
  if (!source_) {
    error = "code source missing";
    return false;
  }

  if (size == 0) {
    error = "block size is zero";
    return false;
  }

  std::vector<std::byte> raw_bytes;
  raw_bytes.resize(size);
  if (!source_->read_by_address(context, address, std::span<std::byte>(raw_bytes), error)) {
    return false;
  }
  std::vector<uint8_t> buffer;
  buffer.resize(raw_bytes.size());
  for (size_t i = 0; i < raw_bytes.size(); ++i) {
    buffer[i] = std::to_integer<uint8_t>(raw_bytes[i]);
  }
  uint64_t base_address = address;

  auto arch_value = trace_arch_to_asmr_arch(context.header.architecture);
  if (!arch_value.has_value()) {
    error = "unsupported trace architecture for asmr decoder";
    return false;
  }

  auto ctx = w1::asmr::context::for_arch(*arch_value);
  if (!ctx.ok()) {
    error = ctx.status_info.message;
    return false;
  }

  auto decoded = ctx.value.disassemble(buffer, base_address);
  if (!decoded.ok()) {
    error = decoded.status_info.message;
    return false;
  }

  if (decoded.value.empty()) {
    error = "disassembly produced no instructions";
    return false;
  }

  out = w1::rewind::replay_decoded_block{};
  out.address = address;
  out.size = size;
  out.instructions.reserve(decoded.value.size());

  uint32_t expected_offset = 0;
  for (const auto& inst : decoded.value) {
    if (inst.bytes.empty()) {
      error = "decoded instruction missing bytes";
      return false;
    }

    if (inst.address < base_address) {
      error = "decoded instruction address underflow";
      return false;
    }

    uint64_t offset64 = inst.address - base_address;
    if (offset64 > std::numeric_limits<uint32_t>::max()) {
      error = "decoded instruction offset too large";
      return false;
    }

    uint32_t offset = static_cast<uint32_t>(offset64);
    uint32_t inst_size = static_cast<uint32_t>(inst.bytes.size());

    if (offset != expected_offset) {
      error = "decoded instructions are not contiguous";
      return false;
    }

    if (offset + inst_size > size) {
      error = "decoded instruction exceeds block size";
      return false;
    }

    w1::rewind::replay_decoded_instruction out_inst{};
    out_inst.offset = offset;
    out_inst.size = inst_size;
    out_inst.bytes = inst.bytes;
    out.instructions.push_back(std::move(out_inst));

    expected_offset = offset + inst_size;
  }

  if (expected_offset != size) {
    error = "decoded instructions do not cover block size";
    return false;
  }

  return true;
#endif
}

} // namespace w1replay
