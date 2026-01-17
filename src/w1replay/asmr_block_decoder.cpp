#include "asmr_block_decoder.hpp"

#include <limits>
#include <memory>
#include <optional>
#include <vector>

#if defined(P1LL_HAS_ASMR)
#include "p1ll/asmr/asmr.hpp"
#include "p1ll/engine/platform/platform.hpp"
#endif

namespace w1replay {

namespace {

#if defined(P1LL_HAS_ASMR)
std::optional<std::string> trace_arch_to_platform_arch(w1::rewind::trace_arch arch) {
  switch (arch) {
  case w1::rewind::trace_arch::x86:
    return std::string("x86");
  case w1::rewind::trace_arch::x86_64:
    return std::string("x64");
  case w1::rewind::trace_arch::aarch64:
    return std::string("arm64");
  default:
    return std::nullopt;
  }
}
#endif

} // namespace

bool asmr_decoder_available() {
#if defined(P1LL_HAS_ASMR) && defined(WITNESS_LIEF_ENABLED)
  return true;
#else
  return false;
#endif
}

asmr_block_decoder::~asmr_block_decoder() = default;

bool asmr_block_decoder::decode_block(
    const w1::rewind::replay_context& context,
    uint64_t module_id,
    uint64_t module_offset,
    uint32_t size,
    w1::rewind::replay_decoded_block& out,
    std::string& error
) {
#if !defined(P1LL_HAS_ASMR)
  (void)context;
  (void)module_id;
  (void)module_offset;
  (void)size;
  (void)out;
  error = "asmr decoder unavailable (build with P1LL_BUILD_ASMR=ON)";
  return false;
#elif !defined(WITNESS_LIEF_ENABLED)
  (void)context;
  (void)module_id;
  (void)module_offset;
  (void)size;
  (void)out;
  error = "asmr decoder unavailable (build with WITNESS_LIEF=ON)";
  return false;
#else
  if (size == 0) {
    error = "block size is zero";
    return false;
  }

  auto module_it = context.modules_by_id.find(module_id);
  if (module_it == context.modules_by_id.end()) {
    error = "module id not found";
    return false;
  }
  if (module_it->second.path.empty()) {
    error = "module path missing";
    return false;
  }

  auto cache_it = modules_.find(module_id);
  if (cache_it == modules_.end() || cache_it->second.path != module_it->second.path || !cache_it->second.binary) {
    auto binary = LIEF::Parser::parse(module_it->second.path);
    if (!binary) {
      error = "failed to parse module: " + module_it->second.path;
      return false;
    }
    module_entry entry{};
    entry.path = module_it->second.path;
    entry.binary = std::move(binary);
    cache_it = modules_.insert_or_assign(module_id, std::move(entry)).first;
  }

  const auto& binary = *cache_it->second.binary;
  uint64_t address = module_offset;
  auto va_type = LIEF::Binary::VA_TYPES::RVA;
  switch (binary.format()) {
  case LIEF::Binary::FORMATS::MACHO: {
    uint64_t imagebase = binary.imagebase();
    if (imagebase > std::numeric_limits<uint64_t>::max() - module_offset) {
      error = "module imagebase + offset overflow";
      return false;
    }
    address = imagebase + module_offset;
    va_type = LIEF::Binary::VA_TYPES::VA;
    break;
  }
  case LIEF::Binary::FORMATS::ELF:
  case LIEF::Binary::FORMATS::PE:
    address = module_offset;
    va_type = LIEF::Binary::VA_TYPES::RVA;
    break;
  default:
    error = "unsupported binary format for block decode";
    return false;
  }

  auto bytes = binary.get_content_from_virtual_address(address, size, va_type);
  if (bytes.empty() || bytes.size() < size) {
    error = "failed to read block bytes";
    return false;
  }

  std::vector<uint8_t> buffer(bytes.begin(), bytes.begin() + size);
  uint64_t base_address = module_it->second.base + module_offset;

  auto arch_value = trace_arch_to_platform_arch(context.header.architecture);
  if (!arch_value.has_value()) {
    error = "unsupported trace architecture for asmr decoder";
    return false;
  }

  p1ll::engine::platform::platform_key platform{};
  platform.arch = *arch_value;
  platform.os.clear();

  auto ctx = p1ll::asmr::context::for_platform(platform);
  if (!ctx.ok()) {
    error = ctx.status.message;
    return false;
  }

  auto decoded = ctx.value.disassemble(buffer, base_address);
  if (!decoded.ok()) {
    error = decoded.status.message;
    return false;
  }

  if (decoded.value.empty()) {
    error = "disassembly produced no instructions";
    return false;
  }

  out = w1::rewind::replay_decoded_block{};
  out.module_id = module_id;
  out.module_offset = module_offset;
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
