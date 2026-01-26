#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "w1rewind/format/trace_format.hpp"

namespace w1rewind {

enum class image_inventory_event_kind : uint8_t { loaded, unloaded };

struct image_inventory_source_event {
  image_inventory_event_kind kind = image_inventory_event_kind::loaded;
  uint64_t base = 0;
  uint64_t size = 0;
  std::string name;
  std::string path;
};

struct image_inventory_snapshot {
  std::vector<w1::rewind::image_record> images;
  std::vector<w1::rewind::image_metadata_record> metadata_records;
  std::vector<w1::rewind::mapping_record> mappings;
};

struct image_inventory_event {
  image_inventory_event_kind kind = image_inventory_event_kind::loaded;
  uint64_t image_id = 0;
  std::optional<w1::rewind::image_record> image;
  std::optional<w1::rewind::image_metadata_record> metadata;
  std::vector<w1::rewind::mapping_record> mappings;
};

struct image_blob_request {
  bool exec_only = true;
  uint64_t max_bytes = 0;
};

class image_blob_sink {
public:
  virtual ~image_blob_sink() = default;
  virtual bool emit_blob(uint64_t image_id, uint64_t offset, std::span<const uint8_t> bytes) = 0;
};

class image_blob_provider {
public:
  virtual ~image_blob_provider() = default;
  virtual bool emit_image_blobs(
      const w1::rewind::image_record& image, std::span<const w1::rewind::mapping_record> mappings,
      const image_blob_request& request, image_blob_sink& sink, std::string& error
  ) = 0;
};

class image_inventory_provider {
public:
  virtual ~image_inventory_provider() = default;

  virtual void reset(const w1::rewind::arch_descriptor_record& arch) = 0;
  virtual image_inventory_snapshot snapshot(uint32_t space_id) = 0;
  virtual std::optional<image_inventory_event> translate_event(
      const image_inventory_source_event& event, uint32_t space_id
  ) = 0;
};

} // namespace w1rewind
