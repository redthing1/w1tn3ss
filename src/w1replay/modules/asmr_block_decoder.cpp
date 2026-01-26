#include "asmr_block_decoder.hpp"

#include "w1replay/memory/memory_view.hpp"

#include <cstddef>
#include <optional>
#include <vector>

#include "w1base/arch_spec.hpp"

#if defined(WITNESS_ASMR_ENABLED)
#include "w1asmr/asmr.hpp"
#endif

namespace w1replay {

namespace {

#if defined(WITNESS_ASMR_ENABLED) && defined(WITNESS_LIEF_ENABLED)
w1::arch::byte_order to_arch_byte_order(w1::rewind::endian order) {
  switch (order) {
  case w1::rewind::endian::little:
    return w1::arch::byte_order::little;
  case w1::rewind::endian::big:
    return w1::arch::byte_order::big;
  case w1::rewind::endian::unknown:
  default:
    return w1::arch::byte_order::unknown;
  }
}

w1::arch::arch_spec resolve_arch_spec(const w1::rewind::replay_context& context, const w1::rewind::flow_step& flow) {
  w1::arch::arch_spec spec{};
  if (!context.arch.has_value()) {
    return spec;
  }

  std::string parse_error;
  w1::arch::arch_spec base{};
  if (w1::arch::parse_arch_spec(context.arch->arch_id, base, parse_error)) {
    spec = base;
  }

  if (context.arch->pointer_bits != 0) {
    spec.pointer_bits = context.arch->pointer_bits;
  }
  if (context.arch->byte_order != w1::rewind::endian::unknown) {
    spec.arch_byte_order = to_arch_byte_order(context.arch->byte_order);
  }

  if (flow.mode_id != 0) {
    for (const auto& mode_entry : context.arch->modes) {
      if (mode_entry.mode_id != flow.mode_id) {
        continue;
      }
      if (mode_entry.name.empty()) {
        break;
      }
      w1::arch::arch_spec mode_spec{};
      if (w1::arch::parse_arch_spec(mode_entry.name, mode_spec, parse_error)) {
        spec.arch_family = mode_spec.arch_family;
        spec.arch_mode = mode_spec.arch_mode;
        if (spec.pointer_bits == 0) {
          spec.pointer_bits = mode_spec.pointer_bits;
        }
        if (spec.arch_byte_order == w1::arch::byte_order::unknown) {
          spec.arch_byte_order = mode_spec.arch_byte_order;
        }
      }
      break;
    }
  }

  return spec;
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
    const w1::rewind::replay_context& context, const w1::rewind::flow_step& flow, w1::rewind::decoded_block& out,
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

  auto read = view_->read(flow.space_id, flow.address, flow.size);
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

  if (!context.arch.has_value()) {
    error = "trace missing arch descriptor";
    return false;
  }

  w1::arch::arch_spec spec = resolve_arch_spec(context, flow);

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

  out = w1::rewind::decoded_block{};
  out.start = flow.address;
  out.size = flow.size;
  out.instructions.reserve(decoded.value.size());

  uint64_t expected_address = base_address;
  for (const auto& inst : decoded.value) {
    if (inst.bytes.empty()) {
      error = "decoded instruction missing bytes";
      return false;
    }

    uint32_t inst_size = static_cast<uint32_t>(inst.bytes.size());

    if (inst.address != expected_address) {
      error = "decoded instructions are not contiguous";
      return false;
    }

    if (inst.address + inst_size < inst.address) {
      error = "decoded instruction address overflow";
      return false;
    }

    if (inst.address + inst_size > base_address + flow.size) {
      error = "decoded instruction exceeds block size";
      return false;
    }

    w1::rewind::decoded_instruction out_inst{};
    out_inst.address = inst.address;
    out_inst.size = inst_size;
    out_inst.bytes = inst.bytes;
    out.instructions.push_back(std::move(out_inst));

    expected_address = inst.address + inst_size;
  }

  if (expected_address != base_address + flow.size) {
    error = "decoded instructions do not cover block size";
    return false;
  }

  return true;
#endif
}

} // namespace w1replay
