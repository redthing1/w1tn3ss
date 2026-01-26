#include "module_catalog_inventory.hpp"

#include <algorithm>
#include <fstream>
#include <limits>
#include <string_view>

namespace {

constexpr uint64_t k_image_id_offset = 1;
constexpr size_t k_image_blob_chunk_size = 1 << 20;

std::string_view basename_view(std::string_view path) {
  const auto pos = path.find_last_of("/\\");
  if (pos == std::string_view::npos) {
    return path;
  }
  return path.substr(pos + 1);
}

bool mapping_is_exec(const w1::rewind::mapping_record& mapping) {
  return (mapping.perms & w1::rewind::mapping_perm::exec) != w1::rewind::mapping_perm::none;
}

uint64_t safe_end(uint64_t base, uint64_t size) {
  if (size == 0) {
    return base;
  }
  uint64_t end = base + size;
  if (end < base) {
    return std::numeric_limits<uint64_t>::max();
  }
  return end;
}

struct blob_range {
  uint64_t offset = 0;
  uint64_t end = 0;
};

std::vector<blob_range> collect_blob_ranges(
    uint64_t image_id, std::span<const w1::rewind::mapping_record> mappings, bool exec_only
) {
  std::vector<blob_range> ranges;
  for (const auto& mapping : mappings) {
    if (mapping.image_id != image_id || mapping.size == 0) {
      continue;
    }
    if (exec_only && !mapping_is_exec(mapping)) {
      continue;
    }
    uint64_t start = mapping.image_offset;
    uint64_t end = safe_end(mapping.image_offset, mapping.size);
    if (end <= start) {
      continue;
    }
    ranges.push_back({start, end});
  }

  if (ranges.empty()) {
    return ranges;
  }

  std::sort(ranges.begin(), ranges.end(), [](const blob_range& a, const blob_range& b) {
    return a.offset < b.offset;
  });

  std::vector<blob_range> merged;
  merged.reserve(ranges.size());
  blob_range current = ranges.front();
  for (size_t i = 1; i < ranges.size(); ++i) {
    const auto& next = ranges[i];
    if (next.offset > current.end) {
      merged.push_back(current);
      current = next;
      continue;
    }
    current.end = std::max(current.end, next.end);
  }
  merged.push_back(current);
  return merged;
}

} // namespace

namespace w1rewind {

module_catalog_image_inventory::module_catalog_image_inventory(
    w1::runtime::module_catalog& modules, w1::core::instrumented_module_policy policy
)
    : modules_(&modules), registry_(std::move(policy)) {}

void module_catalog_image_inventory::reset(const w1::rewind::arch_descriptor_record& arch) {
  arch_ = arch;
  metadata_cache_.emplace(arch_);
  if (modules_) {
    registry_.configure(*modules_);
  }
}

image_inventory_snapshot module_catalog_image_inventory::snapshot(uint32_t space_id) {
  image_inventory_snapshot snapshot;
  if (!modules_) {
    return snapshot;
  }

  modules_->refresh();
  if (!metadata_cache_.has_value()) {
    metadata_cache_.emplace(arch_);
  }

  auto list = modules_->list_modules();
  snapshot.images.reserve(list.size());

  std::vector<image_span> spans;
  spans.reserve(list.size());

  for (const auto& module : list) {
    auto lookup = registry_.find(module.base_address);
    if (!lookup) {
      continue;
    }

    const uint64_t id = lookup->value + k_image_id_offset;
    image_metadata meta{};
    auto image = build_image_record(module, id, *metadata_cache_, &meta);
    snapshot.images.push_back(image);
    snapshot.metadata_records.push_back(build_image_metadata_record(id, meta));

    image_span span{};
    span.image_id = id;
    span.base = module.base_address;
    span.size = module.size;
    span.link_base_valid = meta.link_base_valid;
    span.link_base = meta.link_base;
    spans.push_back(span);
  }

  snapshot.mappings = collect_process_mappings(spans, space_id);
  return snapshot;
}

std::optional<image_inventory_event> module_catalog_image_inventory::translate_event(
    const image_inventory_source_event& event, uint32_t space_id
) {
  if (event.kind != image_inventory_event_kind::loaded && event.kind != image_inventory_event_kind::unloaded) {
    return std::nullopt;
  }

  auto info = find_module_info(event);
  if (!info.has_value()) {
    return std::nullopt;
  }

  if (!metadata_cache_.has_value()) {
    metadata_cache_.emplace(arch_);
  }

  auto lookup = registry_.find(info->base_address);
  if (!lookup) {
    return std::nullopt;
  }

  const uint64_t image_id = lookup->value + k_image_id_offset;
  if (event.kind == image_inventory_event_kind::loaded) {
    return make_loaded_event(*info, image_id, space_id);
  }
  return make_unloaded_event(*info, image_id, space_id);
}

bool module_catalog_image_inventory::emit_image_blobs(
    const w1::rewind::image_record& image, std::span<const w1::rewind::mapping_record> mappings,
    const image_blob_request& request, image_blob_sink& sink, std::string& error
) {
  error.clear();
  const bool must_have_file = (image.flags & w1::rewind::image_flag_file_backed) != 0;
  if (image.path.empty()) {
    if (must_have_file) {
      error = "image path missing";
      return false;
    }
    return true;
  }

  std::ifstream in(image.path, std::ios::binary | std::ios::in);
  if (!in.is_open()) {
    if (must_have_file) {
      error = "failed to open image: " + image.path;
      return false;
    }
    return true;
  }

  in.seekg(0, std::ios::end);
  auto end_pos = in.tellg();
  if (end_pos <= 0) {
    if (must_have_file) {
      error = "image size unavailable";
      return false;
    }
    return true;
  }

  uint64_t file_size = static_cast<uint64_t>(end_pos);
  if (file_size == 0) {
    if (must_have_file) {
      error = "image size empty";
      return false;
    }
    return true;
  }

  auto ranges = collect_blob_ranges(image.image_id, mappings, request.exec_only);
  if (ranges.empty()) {
    if (request.exec_only) {
      return true;
    }
    ranges.push_back({0, file_size});
  }

  uint64_t max_bytes = request.max_bytes;
  uint64_t emitted = 0;

  for (const auto& range : ranges) {
    if (max_bytes != 0 && emitted >= max_bytes) {
      break;
    }

    uint64_t start = range.offset;
    uint64_t end = std::min(range.end, file_size);
    if (start >= end) {
      continue;
    }

    uint64_t cursor = start;
    while (cursor < end) {
      uint64_t remaining = end - cursor;
      if (max_bytes != 0) {
        remaining = std::min(remaining, max_bytes - emitted);
      }
      if (remaining == 0) {
        break;
      }

      size_t chunk_size = static_cast<size_t>(std::min<uint64_t>(remaining, k_image_blob_chunk_size));
      std::vector<uint8_t> buffer(chunk_size);
      in.seekg(static_cast<std::streamoff>(cursor), std::ios::beg);
      if (!in.good()) {
        error = "image read failed";
        return false;
      }
      in.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(chunk_size));
      size_t read = static_cast<size_t>(in.gcount());
      if (read == 0) {
        break;
      }
      buffer.resize(read);

      if (!sink.emit_blob(image.image_id, cursor, std::span<const uint8_t>(buffer.data(), buffer.size()))) {
        error = "failed to emit image blob";
        return false;
      }

      emitted += read;
      cursor += read;
      if (read < chunk_size) {
        break;
      }
    }
  }

  return true;
}

std::optional<w1::runtime::module_info> module_catalog_image_inventory::find_module_info(
    const image_inventory_source_event& event
) const {
  if (!modules_) {
    return std::nullopt;
  }

  const uint64_t base = event.base;
  auto list = modules_->list_modules();

  if (base != 0) {
    auto it = std::find_if(list.begin(), list.end(), [&](const w1::runtime::module_info& module) {
      return module.full_range.start <= base && base < module.full_range.end;
    });
    if (it != list.end()) {
      return *it;
    }
  }

  std::string_view event_path = event.path;
  std::string_view event_name = event.name;
  if (event_name.empty()) {
    event_name = basename_view(event_path);
  }

  if (!event_path.empty() || !event_name.empty()) {
    auto it = std::find_if(list.begin(), list.end(), [&](const w1::runtime::module_info& module) {
      if (!event_path.empty() && (module.path == event_path || module.name == event_path)) {
        return true;
      }
      if (!event_name.empty() && (module.name == event_name || basename_view(module.path) == event_name)) {
        return true;
      }
      return false;
    });
    if (it != list.end()) {
      return *it;
    }
  }

  return std::nullopt;
}

image_inventory_event module_catalog_image_inventory::make_loaded_event(
    const w1::runtime::module_info& module, uint64_t image_id, uint32_t space_id
) {
  image_metadata meta{};
  auto image = build_image_record(module, image_id, *metadata_cache_, &meta);
  auto mapping = build_module_mapping(module, image_id, space_id);

  image_inventory_event event{};
  event.kind = image_inventory_event_kind::loaded;
  event.image_id = image_id;
  event.image = image;
  event.metadata = build_image_metadata_record(image_id, meta);
  if (mapping.size != 0) {
    event.mappings.push_back(mapping);
  }
  return event;
}

image_inventory_event module_catalog_image_inventory::make_unloaded_event(
    const w1::runtime::module_info& module, uint64_t image_id, uint32_t space_id
) {
  auto mapping = build_module_mapping(module, image_id, space_id);
  image_inventory_event event{};
  event.kind = image_inventory_event_kind::unloaded;
  event.image_id = image_id;
  if (mapping.size != 0) {
    event.mappings.push_back(mapping);
  }
  return event;
}

} // namespace w1rewind
