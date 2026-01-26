#pragma once

#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "w1rewind/format/trace_format.hpp"
#include "w1runtime/module_catalog.hpp"

namespace w1rewind {

struct image_metadata {
  std::string kind;
  std::string identity;
  uint32_t identity_age = 0;
  bool link_base_valid = false;
  uint64_t link_base = 0;
  std::optional<uint64_t> entry_point;
  bool file_backed = false;
  bool has_macho_header = false;
  w1::rewind::image_macho_header macho_header{};
  std::vector<w1::rewind::image_segment_record> segments;
};

class image_metadata_cache {
public:
  explicit image_metadata_cache(w1::rewind::arch_descriptor_record arch) : arch_(std::move(arch)) {}

  image_metadata lookup(const std::string& path);

private:
  w1::rewind::arch_descriptor_record arch_{};
  std::unordered_map<std::string, image_metadata> cache_{};
};

struct image_span {
  uint64_t image_id = 0;
  uint64_t base = 0;
  uint64_t size = 0;
  bool link_base_valid = false;
  uint64_t link_base = 0;
};

w1::rewind::image_record build_image_record(
    const w1::runtime::module_info& module, uint64_t image_id, image_metadata_cache& cache,
    image_metadata* metadata_out = nullptr
);

w1::rewind::image_metadata_record build_image_metadata_record(uint64_t image_id, const image_metadata& metadata);

w1::rewind::mapping_record build_module_mapping(
    const w1::runtime::module_info& module, uint64_t image_id, uint32_t space_id
);

std::vector<w1::rewind::mapping_record> collect_process_mappings(
    std::span<const image_span> images, uint32_t space_id
);

} // namespace w1rewind
