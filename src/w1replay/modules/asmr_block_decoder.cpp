#include "asmr_block_decoder.hpp"

#include "w1replay/memory/memory_view.hpp"
#include "w1rewind/replay/flow_cursor.hpp"

#include <cstddef>
#include <limits>
#include <optional>
#include <vector>

#if defined(WITNESS_ASMR_ENABLED)
#include "w1asmr/asmr.hpp"
#endif

namespace w1replay {

namespace {} // namespace

bool asmr_decoder_available() {
#if defined(WITNESS_ASMR_ENABLED) && defined(WITNESS_LIEF_ENABLED)
  return true;
#else
  return false;
#endif
}

asmr_block_decoder::~asmr_block_decoder() = default;

bool asmr_block_decoder::decode_block(
    const w1::rewind::replay_context& context, const w1::rewind::flow_step& flow, w1::rewind::replay_decoded_block& out,
    std::string& error
) {
#if !defined(WITNESS_ASMR_ENABLED)
  (void) context;
  (void) flow;
  (void) out;
  error = "asmr decoder unavailable (build with WITNESS_ASMR=ON)";
  return false;
#elif !defined(WITNESS_LIEF_ENABLED)
  (void) context;
  (void) flow;
  (void) out;
  error = "asmr decoder unavailable (build with WITNESS_LIEF=ON)";
  return false;
#else
  if (!view_) {
    error = "memory view missing";
    return false;
  }

  if (flow.size == 0) {
    error = "block size is zero";
    return false;
  }

  auto read = view_->read(flow.address, flow.size);
  if (!read.complete()) {
    error = "code bytes incomplete";
    return false;
  }
  if (read.bytes.size() < flow.size) {
    error = "code bytes truncated";
    return false;
  }
  std::vector<uint8_t> buffer;
  buffer.resize(read.bytes.size());
  for (size_t i = 0; i < read.bytes.size(); ++i) {
    buffer[i] = std::to_integer<uint8_t>(read.bytes[i]);
  }
  uint64_t base_address = flow.address;

  w1::arch::arch_spec spec = context.header.arch;
  if ((flow.flags & w1::rewind::trace_block_flag_mode_valid) != 0) {
    if ((flow.flags & w1::rewind::trace_block_flag_thumb) != 0) {
      spec.arch_mode = w1::arch::mode::thumb;
    } else {
      spec.arch_mode = w1::arch::mode::arm;
    }
  }

  auto ctx = w1::asmr::disasm_context::for_arch(spec);
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
  out.address = flow.address;
  out.size = flow.size;
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

    if (offset + inst_size > flow.size) {
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

  if (expected_offset != flow.size) {
    error = "decoded instructions do not cover block size";
    return false;
  }

  return true;
#endif
}

} // namespace w1replay
