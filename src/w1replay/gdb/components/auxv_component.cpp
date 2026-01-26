#include "w1replay/gdb/adapter_components.hpp"

#include <limits>

namespace w1replay::gdb {

namespace {

constexpr uint64_t k_auxv_at_null = 0;
constexpr uint64_t k_auxv_at_entry = 9;

struct mapping_view {
  const w1::rewind::mapping_record* mapping = nullptr;
  uint64_t base = 0;
  uint64_t image_offset = 0;
};

bool add_overflows(uint64_t base, uint64_t addend) { return base > std::numeric_limits<uint64_t>::max() - addend; }

const w1::rewind::image_record* find_main_image(const adapter_services& services) {
  if (!services.context) {
    return nullptr;
  }
  for (const auto& image : services.context->images) {
    if ((image.flags & w1::rewind::image_flag_main) != 0) {
      return &image;
    }
  }
  if (services.session && services.image_index) {
    uint64_t pc = services.session->current_step().address;
    auto match = services.image_index->find(pc, 1);
    if (match && match->image) {
      return match->image;
    }
  }
  return nullptr;
}

std::vector<mapping_view> collect_mappings(const adapter_services& services, uint32_t space_id) {
  std::vector<mapping_view> out;
  if (services.mappings) {
    auto it = services.mappings->ranges_by_space().find(space_id);
    if (it == services.mappings->ranges_by_space().end()) {
      return out;
    }
    out.reserve(it->second.size());
    for (const auto& range : it->second) {
      if (!range.mapping || range.end <= range.start) {
        continue;
      }
      if (range.start < range.mapping->base) {
        continue;
      }
      uint64_t delta = range.start - range.mapping->base;
      if (add_overflows(range.mapping->image_offset, delta)) {
        continue;
      }
      out.push_back({range.mapping, range.start, range.mapping->image_offset + delta});
    }
    return out;
  }

  if (!services.context) {
    return out;
  }
  out.reserve(services.context->mappings.size());
  for (const auto& mapping : services.context->mappings) {
    if (mapping.space_id != space_id || mapping.size == 0) {
      continue;
    }
    out.push_back({&mapping, mapping.base, mapping.image_offset});
  }
  return out;
}

std::optional<uint64_t> compute_runtime_entrypoint(
    const adapter_services& services, const w1::rewind::image_record& image
) {
  if (!services.context) {
    return std::nullopt;
  }
  const auto* meta = services.context->find_image_metadata(image.image_id);
  if (!meta) {
    return std::nullopt;
  }
  if ((meta->flags & w1::rewind::image_meta_has_entry_point) == 0 ||
      (meta->flags & w1::rewind::image_meta_has_link_base) == 0) {
    return std::nullopt;
  }
  const uint64_t entry = meta->entry_point;
  const uint64_t link_base = meta->link_base;

  auto mappings = collect_mappings(services, 0);
  for (const auto& view : mappings) {
    if (!view.mapping || view.mapping->image_id != image.image_id) {
      continue;
    }
    if (add_overflows(link_base, view.image_offset)) {
      continue;
    }
    uint64_t mapped_base = link_base + view.image_offset;
    if (view.base < mapped_base) {
      continue;
    }
    if (entry < link_base) {
      continue;
    }
    uint64_t offset = entry - link_base;
    if (view.base > std::numeric_limits<uint64_t>::max() - offset) {
      continue;
    }
    return view.base + offset;
  }

  return std::nullopt;
}

bool append_auxv_entry(std::vector<std::byte>& out, uint64_t type, uint64_t value, size_t word_size, endian order) {
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
  if (!services_.context || !services_.context->environment) {
    return std::nullopt;
  }
  if (services_.context->environment->os_id != "linux") {
    return std::nullopt;
  }

  uint32_t pointer_bits = 0;
  if (services_.context->arch.has_value()) {
    pointer_bits = services_.context->arch->pointer_bits;
  }
  if (pointer_bits == 0 || pointer_bits % 8 != 0) {
    return std::nullopt;
  }
  size_t word_size = pointer_bits / 8;
  if (word_size == 0 || word_size > sizeof(uint64_t)) {
    return std::nullopt;
  }

  const auto* image = find_main_image(services_);
  if (!image) {
    return std::nullopt;
  }
  auto entry = compute_runtime_entrypoint(services_, *image);
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
