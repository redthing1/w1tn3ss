#include "image_inventory_pipeline.hpp"

#include <algorithm>

namespace w1rewind {

namespace {

class builder_blob_sink final : public image_blob_sink {
public:
  explicit builder_blob_sink(w1::rewind::trace_builder* builder) : builder_(builder) {}

  bool emit_blob(uint64_t image_id, uint64_t offset, std::span<const uint8_t> bytes) override {
    if (!builder_) {
      return false;
    }
    return builder_->emit_image_blob_range(image_id, offset, bytes);
  }

private:
  w1::rewind::trace_builder* builder_ = nullptr;
};

} // namespace

image_inventory_pipeline::image_inventory_pipeline(redlog::logger log) : log_(std::move(log)) {}

void image_inventory_pipeline::reset() {
  images_.clear();
  metadata_records_.clear();
  mappings_.clear();
  emitted_images_.clear();
  emitted_metadata_.clear();
  emitted_blob_images_.clear();
}

void image_inventory_pipeline::snapshot(image_inventory_provider& provider, uint32_t space_id) {
  reset();
  auto snapshot = provider.snapshot(space_id);
  images_ = std::move(snapshot.images);
  metadata_records_ = std::move(snapshot.metadata_records);
  mappings_ = std::move(snapshot.mappings);
  for (auto& mapping : mappings_) {
    mapping.kind = w1::rewind::mapping_event_kind::map;
  }
  emitted_images_.reserve(images_.size());
  for (const auto& image : images_) {
    emitted_images_.insert(image.image_id);
  }
  emitted_metadata_.reserve(metadata_records_.size());
  for (const auto& meta : metadata_records_) {
    emitted_metadata_.insert(meta.image_id);
  }
}

bool image_inventory_pipeline::emit_snapshot(
    w1::rewind::trace_builder& builder, bool blobs_enabled, const image_blob_request& request,
    image_blob_provider* blob_provider
) {
  for (const auto& image : images_) {
    if (!builder.emit_image(image)) {
      log_.err("failed to write image record", redlog::field("error", builder.error()));
      return false;
    }
  }

  for (const auto& meta : metadata_records_) {
    if (!builder.emit_image_metadata(meta)) {
      log_.err("failed to write image metadata record", redlog::field("error", builder.error()));
      return false;
    }
    emitted_metadata_.insert(meta.image_id);
  }

  for (const auto& mapping : mappings_) {
    if (!builder.emit_mapping(mapping)) {
      log_.err("failed to write mapping record", redlog::field("error", builder.error()));
      return false;
    }
  }

  emit_image_blobs(builder, blobs_enabled, request, blob_provider);

  return true;
}

void image_inventory_pipeline::apply_event(
    const image_inventory_event& event, w1::rewind::trace_builder* builder, bool trace_ready, bool blobs_enabled,
    const image_blob_request& request, image_blob_provider* blob_provider
) {
  const uint64_t image_id = event.image.has_value() ? event.image->image_id : event.image_id;

  if (event.kind == image_inventory_event_kind::loaded) {
    if (event.image.has_value()) {
      const bool inserted = emitted_images_.insert(image_id).second;
      if (inserted) {
        images_.push_back(*event.image);
      }
      if (trace_ready && builder && builder->good()) {
        if (!builder->emit_image(*event.image)) {
          log_.err("failed to write image record", redlog::field("error", builder->error()));
        }
      }
    }
    if (event.metadata.has_value()) {
      const bool inserted_meta = emitted_metadata_.insert(image_id).second;
      if (inserted_meta) {
        metadata_records_.push_back(*event.metadata);
      }
      if (trace_ready && builder && builder->good()) {
        if (!builder->emit_image_metadata(*event.metadata)) {
          log_.err("failed to write image metadata record", redlog::field("error", builder->error()));
        }
      }
    }

    for (auto mapping : event.mappings) {
      if (mapping.size == 0) {
        continue;
      }
      mapping.kind = w1::rewind::mapping_event_kind::map;
      mappings_.push_back(mapping);
      if (trace_ready && builder && builder->good()) {
        if (!builder->emit_mapping(mapping)) {
          log_.err("failed to write mapping record", redlog::field("error", builder->error()));
        }
      }
    }
    if (event.image.has_value() && builder && builder->good()) {
      emit_image_blobs_for_image(*event.image, *builder, blobs_enabled, request, blob_provider);
    }
    return;
  }

  emitted_images_.erase(image_id);
  emitted_metadata_.erase(image_id);
  emitted_blob_images_.erase(image_id);
  images_.erase(
      std::remove_if(
          images_.begin(), images_.end(),
          [&](const w1::rewind::image_record& record) { return record.image_id == image_id; }
      ),
      images_.end()
  );
  metadata_records_.erase(
      std::remove_if(
          metadata_records_.begin(), metadata_records_.end(),
          [&](const w1::rewind::image_metadata_record& record) { return record.image_id == image_id; }
      ),
      metadata_records_.end()
  );

  if (event.mappings.empty()) {
    for (const auto& mapping : mappings_) {
      if (mapping.image_id == image_id) {
        emit_unmap(mapping, builder, trace_ready);
      }
    }
    mappings_.erase(
        std::remove_if(
            mappings_.begin(), mappings_.end(),
            [&](const w1::rewind::mapping_record& record) { return record.image_id == image_id; }
        ),
        mappings_.end()
    );
    return;
  }

  for (const auto& mapping : event.mappings) {
    for (const auto& existing : mappings_) {
      if (existing.image_id == image_id && existing.space_id == mapping.space_id && existing.base == mapping.base &&
          existing.size == mapping.size) {
        emit_unmap(existing, builder, trace_ready);
        break;
      }
    }
    mappings_.erase(
        std::remove_if(
            mappings_.begin(), mappings_.end(),
            [&](const w1::rewind::mapping_record& record) {
              return record.image_id == image_id && record.space_id == mapping.space_id &&
                     record.base == mapping.base && record.size == mapping.size;
            }
        ),
        mappings_.end()
    );
  }
}

void image_inventory_pipeline::emit_image_blobs(
    w1::rewind::trace_builder& builder, bool blobs_enabled, const image_blob_request& request,
    image_blob_provider* blob_provider
) {
  if (!blobs_enabled || !builder.good()) {
    return;
  }
  for (const auto& image : images_) {
    emit_image_blobs_for_image(image, builder, blobs_enabled, request, blob_provider);
  }
}

void image_inventory_pipeline::emit_image_blobs_for_image(
    const w1::rewind::image_record& image, w1::rewind::trace_builder& builder, bool blobs_enabled,
    const image_blob_request& request, image_blob_provider* blob_provider
) {
  if (!blobs_enabled || !builder.good()) {
    return;
  }
  if (emitted_blob_images_.find(image.image_id) != emitted_blob_images_.end()) {
    return;
  }

  if (!blob_provider) {
    log_.err("image blob provider missing");
    emitted_blob_images_.insert(image.image_id);
    return;
  }

  builder_blob_sink sink(&builder);
  std::string error;
  if (!blob_provider->emit_image_blobs(
          image, std::span<const w1::rewind::mapping_record>(mappings_), request, sink, error
      )) {
    log_.err(
        "failed to emit image blobs", redlog::field("image_id", image.image_id),
        redlog::field("error", error.empty() ? "unknown error" : error)
    );
  }
  emitted_blob_images_.insert(image.image_id);
}

void image_inventory_pipeline::emit_unmap(
    const w1::rewind::mapping_record& mapping, w1::rewind::trace_builder* builder, bool trace_ready
) {
  if (!trace_ready || !builder || !builder->good()) {
    return;
  }
  w1::rewind::mapping_record record = mapping;
  record.kind = w1::rewind::mapping_event_kind::unmap;
  record.perms = w1::rewind::mapping_perm::none;
  record.flags = 0;
  record.name.clear();
  if (!builder->emit_mapping(record)) {
    log_.err("failed to write mapping record", redlog::field("error", builder->error()));
  }
}

} // namespace w1rewind
