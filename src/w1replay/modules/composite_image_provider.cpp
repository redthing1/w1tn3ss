#include "composite_image_provider.hpp"

#include <algorithm>
#include <limits>
#include <optional>

#include "address_read_cursor.hpp"
#include "image_blob_reader.hpp"
#include "image_layout_from_metadata.hpp"
#include "w1rewind/replay/replay_context.hpp"
#include "w1rewind/replay/mapping_state.hpp"

namespace w1replay {

composite_image_provider::composite_image_provider(composite_image_provider_config config)
    : context_(config.context), resolver_(config.resolver), address_index_(config.address_index),
      mapping_state_(config.mapping_state), layout_provider_(std::move(config.layout_provider)),
      address_reader_(std::move(config.address_reader)), metadata_provider_(config.context) {}

std::string composite_image_provider::resolved_image_path(const w1::rewind::image_record& image) const {
  if ((image.flags & w1::rewind::image_flag_file_backed) == 0) {
    return {};
  }
  if (resolver_) {
    if (auto resolved = resolver_->resolve_image_path(image)) {
      return *resolved;
    }
  }
  return {};
}

const w1::rewind::image_blob_index* composite_image_provider::blob_index_for_image(
    uint64_t image_id, std::string& error
) {
  error.clear();
  if (!context_) {
    return nullptr;
  }
  if (auto* index = context_->find_image_blob_index(image_id)) {
    return index;
  }
  auto cache_it = blob_index_cache_.find(image_id);
  if (cache_it != blob_index_cache_.end()) {
    return &cache_it->second;
  }
  auto it = context_->image_blobs_by_id.find(image_id);
  if (it == context_->image_blobs_by_id.end()) {
    return nullptr;
  }
  w1::rewind::image_blob_index index{};
  if (!w1::rewind::build_image_blob_index(it->second, index, error)) {
    return nullptr;
  }
  if (index.spans.empty()) {
    return nullptr;
  }
  auto result = blob_index_cache_.emplace(image_id, std::move(index));
  return &result.first->second;
}

image_read_result composite_image_provider::read_image_bytes(
    const w1::rewind::image_record& image, uint64_t offset, size_t size
) {
  image_read_result result = make_empty_image_read(size);
  if (size == 0) {
    result.error = "image read size is zero";
    return result;
  }

  std::string last_error;
  auto merge_source = [&](const image_read_result& source) {
    if (!source.error.empty()) {
      last_error = source.error;
    }
    merge_image_bytes(result, source);
  };

  if (context_) {
    std::string blob_error;
    if (auto* index = blob_index_for_image(image.image_id, blob_error)) {
      merge_source(read_image_blob_index(*index, offset, size));
    } else if (!blob_error.empty()) {
      last_error = blob_error;
    }
  }

  const std::string path = resolved_image_path(image);

  if (!result.complete && !path.empty()) {
    std::string layout_error;
    const auto* layout = layout_for_image(image, layout_error);
    if (layout) {
      merge_source(w1replay::read_image_bytes(*layout, offset, size));
    } else if (!layout_error.empty()) {
      last_error = layout_error;
    }
  }

  if (!any_known(result)) {
    result.error = last_error.empty() ? "image bytes unavailable" : last_error;
  }
  return result;
}

image_read_result composite_image_provider::read_address_bytes(
    const w1::rewind::replay_context& context, uint64_t address, size_t size, uint32_t space_id
) {
  const auto* blob_context = context_ ? context_ : &context;
  const image_address_index* index = address_index_;
  std::optional<image_address_index> stack_index;
  std::unordered_map<uint64_t, w1::rewind::image_blob_index> temp_blob_indexes;
  if (!index) {
    if (context_) {
      if (!fallback_index_) {
        fallback_index_ = std::make_unique<image_address_index>(*context_, mapping_state_);
      }
      index = fallback_index_.get();
    } else {
      stack_index.emplace(context, mapping_state_);
      index = &*stack_index;
    }
  }
  auto find_blob_index = [&](const w1::rewind::replay_context& ctx, uint64_t image_id, std::string& error)
      -> const w1::rewind::image_blob_index* {
    if (&ctx == context_) {
      return blob_index_for_image(image_id, error);
    }
    auto cache_it = temp_blob_indexes.find(image_id);
    if (cache_it != temp_blob_indexes.end()) {
      return cache_it->second.spans.empty() ? nullptr : &cache_it->second;
    }
    auto it = ctx.image_blobs_by_id.find(image_id);
    if (it == ctx.image_blobs_by_id.end()) {
      return nullptr;
    }
    w1::rewind::image_blob_index index{};
    if (!w1::rewind::build_image_blob_index(it->second, index, error)) {
      return nullptr;
    }
    auto result = temp_blob_indexes.emplace(image_id, std::move(index));
    return result.first->second.spans.empty() ? nullptr : &result.first->second;
  };
  address_read_sources sources{};
  sources.blob_index = [&](const w1::rewind::image_record& image, std::string& error) {
    return blob_context ? find_blob_index(*blob_context, image.image_id, error) : nullptr;
  };
  sources.read_blob = [](const w1::rewind::image_blob_index& blob_index, uint64_t image_offset, size_t chunk) {
    return read_image_blob_index(blob_index, image_offset, chunk);
  };
  sources.read_address = address_reader_;
  sources.read_image = [&](const w1::rewind::image_record& image, uint64_t image_offset, size_t chunk,
                           std::string& error) {
    const std::string path = resolved_image_path(image);
    if (path.empty()) {
      return image_read_result{};
    }
    const auto* layout = layout_for_image(image, error);
    if (!layout) {
      return image_read_result{};
    }
    return w1replay::read_image_bytes(*layout, image_offset, chunk);
  };
  return read_address_bytes_with_sources(*blob_context, mapping_state_, *index, address, size, space_id, sources);
}

const image_layout* composite_image_provider::layout_for_image(
    const w1::rewind::image_record& image, std::string& error
) {
  error.clear();
  auto* entry = get_or_load_entry(image, error);
  if (!entry) {
    return nullptr;
  }
  return &entry->layout;
}

std::optional<std::string> composite_image_provider::image_uuid(
    const w1::rewind::image_record& image, std::string& error
) {
  return metadata_provider_.image_uuid(image, error);
}

std::optional<macho_header_info> composite_image_provider::macho_header(
    const w1::rewind::image_record& image, std::string& error
) {
  return metadata_provider_.macho_header(image, error);
}

std::vector<macho_segment_info> composite_image_provider::macho_segments(
    const w1::rewind::image_record& image, std::string& error
) {
  return metadata_provider_.macho_segments(image, error);
}

composite_image_provider::image_entry* composite_image_provider::get_or_load_entry(
    const w1::rewind::image_record& image, std::string& error
) {
  if (!context_) {
    error = "image metadata unavailable";
    return nullptr;
  }

  const auto* meta = context_->find_image_metadata(image.image_id);
  const bool has_meta_layout =
      meta && !meta->segments.empty() && (meta->flags & w1::rewind::image_meta_has_segments) != 0;

  std::string path = resolved_image_path(image);
  if (path.empty()) {
    error = "image path missing";
    return nullptr;
  }

  auto it = images_.find(image.image_id);
  if (it != images_.end()) {
    if (it->second.path == path && !it->second.layout.ranges.empty()) {
      return &it->second;
    }
  }

  image_entry entry{};
  entry.path = path;
  if (has_meta_layout) {
    if (!build_layout_from_metadata(*meta, path, entry.layout, error)) {
      return nullptr;
    }
  } else if (layout_provider_) {
    image_layout_identity layout_identity{};
    if (!layout_provider_->build_layout(image, meta, path, entry.layout, &layout_identity, error)) {
      if (error.empty()) {
        error = "image layout provider failed";
      }
      return nullptr;
    }
    std::optional<std::string> expected_identity;
    std::optional<uint32_t> expected_age;
    if (meta && (meta->flags & w1::rewind::image_meta_has_uuid) != 0 && !meta->uuid.empty()) {
      expected_identity = meta->uuid;
    } else if (!image.identity.empty()) {
      expected_identity = image.identity;
    }
    if (meta && (meta->flags & w1::rewind::image_meta_has_identity_age) != 0) {
      expected_age = meta->identity_age;
    }
    if (expected_identity.has_value() && !layout_identity.identity.empty() &&
        layout_identity.identity != *expected_identity) {
      error = "image identity mismatch";
      return nullptr;
    }
    if (expected_age.has_value() && layout_identity.age.has_value() && *layout_identity.age != *expected_age) {
      error = "image identity age mismatch";
      return nullptr;
    }
  } else {
    error = meta ? "image metadata missing segments" : "image metadata missing";
    return nullptr;
  }
  auto result = images_.insert_or_assign(image.image_id, std::move(entry));
  return &result.first->second;
}

} // namespace w1replay
