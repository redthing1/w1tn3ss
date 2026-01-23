#include "w1replay/gdb/adapter_components.hpp"

#include <limits>
#include "w1rewind/format/trace_format.hpp"

namespace w1replay::gdb {

namespace {

constexpr uint64_t k_auxv_at_null = 0;
constexpr uint64_t k_auxv_at_entry = 9;

bool entry_in_module(const w1::rewind::module_record& module, uint64_t entry) {
  if (module.size == 0) {
    return true;
  }
  if (entry < module.base) {
    return false;
  }
  uint64_t end = module.base + module.size;
  if (end < module.base) {
    return false;
  }
  return entry < end;
}

std::optional<uint64_t> compute_runtime_entrypoint(
    const w1::rewind::module_record& module
) {
  if ((module.flags & w1::rewind::module_record_flag_entry_point_valid) == 0) {
    return std::nullopt;
  }
  if ((module.flags & w1::rewind::module_record_flag_link_base_valid) == 0) {
    return std::nullopt;
  }
  const uint64_t entry = module.entry_point;
  const uint64_t link_base = module.link_base;
  if (entry < link_base) {
    return std::nullopt;
  }
  uint64_t offset = entry - link_base;
  if (module.base > std::numeric_limits<uint64_t>::max() - offset) {
    return std::nullopt;
  }
  uint64_t runtime_entry = module.base + offset;
  if (!entry_in_module(module, runtime_entry)) {
    return std::nullopt;
  }
  return runtime_entry;
}

bool is_elf_file_backed(const w1::rewind::module_record& module) {
  return (module.flags & w1::rewind::module_record_flag_file_backed) != 0 &&
         module.format == w1::rewind::module_format::elf;
}

std::optional<uint64_t> select_entrypoint(const adapter_services& services) {
  if (!services.context) {
    return std::nullopt;
  }

  const auto& modules = services.context->modules;
  for (const auto& module : modules) {
    if ((module.flags & w1::rewind::module_record_flag_main) == 0) {
      continue;
    }
    if (!is_elf_file_backed(module)) {
      return std::nullopt;
    }
    return compute_runtime_entrypoint(module);
  }

  if (services.session && services.module_index) {
    uint64_t pc = services.session->current_step().address;
    auto match = services.module_index->find(pc, 1);
    if (match && match->module && is_elf_file_backed(*match->module)) {
      if (auto entry = compute_runtime_entrypoint(*match->module)) {
        return entry;
      }
    }
  }

  std::optional<uint64_t> best;
  uint64_t best_base = 0;
  for (const auto& module : modules) {
    if (!is_elf_file_backed(module)) {
      continue;
    }
    auto entry = compute_runtime_entrypoint(module);
    if (!entry) {
      continue;
    }
    if (!best || module.base < best_base) {
      best = entry;
      best_base = module.base;
    }
  }

  return best;
}

bool append_auxv_entry(
    std::vector<std::byte>& out,
    uint64_t type,
    uint64_t value,
    size_t word_size,
    endian order
) {
  size_t offset = out.size();
  out.resize(offset + word_size * 2);
  auto type_span = std::span<std::byte>(out.data() + offset, word_size);
  auto value_span = std::span<std::byte>(out.data() + offset + word_size, word_size);
  if (!encode_uint64(type, word_size, type_span, order)) {
    return false;
  }
  if (!encode_uint64(value, word_size, value_span, order)) {
    return false;
  }
  return true;
}

} // namespace

auxv_component::auxv_component(const adapter_services& services) : services_(services) {}

std::optional<std::vector<std::byte>> auxv_component::auxv_data() const {
  if (auxv_cached_) {
    return auxv_data_;
  }
  auxv_cached_ = true;
  auxv_data_ = build_auxv();
  return auxv_data_;
}

std::optional<std::vector<std::byte>> auxv_component::build_auxv() const {
  if (!services_.context || !services_.context->target_info) {
    return std::nullopt;
  }
  if (services_.context->target_info->os != "linux") {
    return std::nullopt;
  }

  uint32_t pointer_bits = services_.context->header.arch.pointer_bits;
  if (pointer_bits == 0 || pointer_bits % 8 != 0) {
    return std::nullopt;
  }
  size_t word_size = pointer_bits / 8;
  if (word_size == 0 || word_size > sizeof(uint64_t)) {
    return std::nullopt;
  }

  auto entry = select_entrypoint(services_);
  if (!entry) {
    return std::nullopt;
  }

  std::vector<std::byte> auxv;
  auxv.reserve(word_size * 4);
  if (!append_auxv_entry(auxv, k_auxv_at_entry, *entry, word_size, services_.target_endian)) {
    return std::nullopt;
  }
  if (!append_auxv_entry(auxv, k_auxv_at_null, 0, word_size, services_.target_endian)) {
    return std::nullopt;
  }
  return auxv;
}

} // namespace w1replay::gdb
