#include "w1replay/gdb/adapter_components.hpp"

#include <unordered_map>

namespace w1replay::gdb {

namespace {

bool is_file_backed(const w1::rewind::image_record& image) {
  return (image.flags & w1::rewind::image_flag_file_backed) != 0;
}

void accumulate_image_bases(
    std::unordered_map<uint64_t, uint64_t>& image_bases, const adapter_services& services, uint32_t space_id
) {
  if (services.mappings) {
    auto it = services.mappings->ranges_by_space().find(space_id);
    if (it == services.mappings->ranges_by_space().end()) {
      return;
    }
    for (const auto& range : it->second) {
      if (!range.mapping || range.end <= range.start) {
        continue;
      }
      if (range.mapping->image_id == 0) {
        continue;
      }
      auto base_it = image_bases.find(range.mapping->image_id);
      if (base_it == image_bases.end() || range.start < base_it->second) {
        image_bases[range.mapping->image_id] = range.start;
      }
    }
    return;
  }

  if (!services.context) {
    return;
  }
  for (const auto& mapping : services.context->mappings) {
    if (mapping.space_id != space_id || mapping.image_id == 0 || mapping.size == 0) {
      continue;
    }
    auto base_it = image_bases.find(mapping.image_id);
    if (base_it == image_bases.end() || mapping.base < base_it->second) {
      image_bases[mapping.image_id] = mapping.base;
    }
  }
}

std::optional<std::string> resolve_image_path(
    const image_path_resolver* resolver, const w1::rewind::image_record& image
) {
  if (resolver) {
    if (auto resolved = resolver->resolve_image_path(image)) {
      return resolved;
    }
  }
  if (!image.path.empty()) {
    return image.path;
  }
  if (!image.identity.empty()) {
    return image.identity;
  }
  if (!image.name.empty()) {
    return image.name;
  }
  return std::nullopt;
}

std::optional<uint64_t> resolve_main_image_id(const adapter_services& services) {
  if (!services.context) {
    return std::nullopt;
  }
  for (const auto& image : services.context->images) {
    if ((image.flags & w1::rewind::image_flag_main) != 0) {
      return image.image_id;
    }
  }
  if (!services.session || !services.image_index) {
    return std::nullopt;
  }
  uint64_t pc = services.session->current_step().address;
  auto match = services.image_index->find(pc, 1);
  if (!match || !match->image) {
    return std::nullopt;
  }
  if (!is_file_backed(*match->image)) {
    return std::nullopt;
  }
  return match->image->image_id;
}

} // namespace

libraries_component::libraries_component(const adapter_services& services) : services_(services) {}

std::vector<gdbstub::library_entry> libraries_component::libraries() const {
  if (!services_.context) {
    return {};
  }

  std::unordered_map<uint64_t, uint64_t> image_bases;
  accumulate_image_bases(image_bases, services_, 0);

  const auto main_image_id = resolve_main_image_id(services_);
  std::vector<gdbstub::library_entry> out;
  out.reserve(services_.context->images.size());

  for (const auto& image : services_.context->images) {
    if (main_image_id && image.image_id == *main_image_id) {
      continue;
    }
    if (!is_file_backed(image)) {
      continue;
    }
    auto base_it = image_bases.find(image.image_id);
    if (base_it == image_bases.end()) {
      continue;
    }
    auto path = resolve_image_path(services_.image_resolver, image);
    if (!path.has_value() || path->empty()) {
      continue;
    }
    out.push_back(gdbstub::library_entry::section(*path, {base_it->second}));
  }

  return out;
}

std::optional<uint64_t> libraries_component::libraries_generation() const {
  if (!services_.context) {
    return std::nullopt;
  }
  const auto main_image_id = resolve_main_image_id(services_);
  uint64_t count = 0;
  for (const auto& image : services_.context->images) {
    if (main_image_id && image.image_id == *main_image_id) {
      continue;
    }
    if (!is_file_backed(image)) {
      continue;
    }
    if (!resolve_image_path(services_.image_resolver, image).has_value()) {
      continue;
    }
    ++count;
  }
  return count;
}

} // namespace w1replay::gdb
