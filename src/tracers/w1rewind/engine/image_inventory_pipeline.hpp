#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <unordered_set>
#include <vector>

#include <redlog.hpp>

#include "engine/image_inventory.hpp"
#include "w1rewind/record/trace_builder.hpp"

namespace w1rewind {

class image_inventory_pipeline {
public:
  explicit image_inventory_pipeline(redlog::logger log);

  void reset();
  void snapshot(image_inventory_provider& provider, uint32_t space_id);

  bool emit_snapshot(
      w1::rewind::trace_builder& builder, bool blobs_enabled, const image_blob_request& request,
      image_blob_provider* blob_provider
  );

  void apply_event(
      const image_inventory_event& event, w1::rewind::trace_builder* builder, bool trace_ready, bool blobs_enabled,
      const image_blob_request& request, image_blob_provider* blob_provider
  );

  size_t image_count() const { return images_.size(); }
  const std::vector<w1::rewind::mapping_record>& mappings() const { return mappings_; }

private:
  void emit_image_blobs(
      w1::rewind::trace_builder& builder, bool blobs_enabled, const image_blob_request& request,
      image_blob_provider* blob_provider
  );

  void emit_image_blobs_for_image(
      const w1::rewind::image_record& image, w1::rewind::trace_builder& builder, bool blobs_enabled,
      const image_blob_request& request, image_blob_provider* blob_provider
  );

  void emit_unmap(const w1::rewind::mapping_record& mapping, w1::rewind::trace_builder* builder, bool trace_ready);

  redlog::logger log_;
  std::vector<w1::rewind::image_record> images_{};
  std::vector<w1::rewind::image_metadata_record> metadata_records_{};
  std::vector<w1::rewind::mapping_record> mappings_{};
  std::unordered_set<uint64_t> emitted_images_{};
  std::unordered_set<uint64_t> emitted_metadata_{};
  std::unordered_set<uint64_t> emitted_blob_images_{};
};

} // namespace w1rewind
