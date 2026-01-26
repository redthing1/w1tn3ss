#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "address_index.hpp"
#include "image_reader.hpp"
#include "image_layout_provider.hpp"
#include "metadata_provider.hpp"
#include "path_resolver.hpp"
#include "trace_metadata_provider.hpp"

namespace w1::rewind {
class mapping_state;
} // namespace w1::rewind

namespace w1replay {

struct composite_image_provider_config {
  const w1::rewind::replay_context* context = nullptr;
  const image_path_resolver* resolver = nullptr;
  const image_address_index* address_index = nullptr;
  const w1::rewind::mapping_state* mapping_state = nullptr;
  std::shared_ptr<image_layout_provider> layout_provider;
  image_address_reader address_reader{};
};

class composite_image_provider final : public image_reader, public image_metadata_provider {
public:
  explicit composite_image_provider(composite_image_provider_config config);

  image_read_result read_image_bytes(const w1::rewind::image_record& image, uint64_t offset, size_t size) override;
  image_read_result read_address_bytes(
      const w1::rewind::replay_context& context, uint64_t address, size_t size, uint32_t space_id = 0
  ) override;
  const image_layout* layout_for_image(const w1::rewind::image_record& image, std::string& error) override;

  std::optional<std::string> image_uuid(const w1::rewind::image_record& image, std::string& error) override;
  std::optional<macho_header_info> macho_header(const w1::rewind::image_record& image, std::string& error) override;
  std::vector<macho_segment_info> macho_segments(const w1::rewind::image_record& image, std::string& error) override;

private:
  std::string resolved_image_path(const w1::rewind::image_record& image) const;
  const w1::rewind::image_blob_index* blob_index_for_image(uint64_t image_id, std::string& error);

  const w1::rewind::replay_context* context_ = nullptr;
  const image_path_resolver* resolver_ = nullptr;
  const image_address_index* address_index_ = nullptr;
  const w1::rewind::mapping_state* mapping_state_ = nullptr;
  std::shared_ptr<image_layout_provider> layout_provider_;
  image_address_reader address_reader_{};
  trace_image_metadata_provider metadata_provider_;

  struct image_entry {
    std::string path;
    image_layout layout;
  };

  std::unordered_map<uint64_t, image_entry> images_;
  std::unordered_map<uint64_t, w1::rewind::image_blob_index> blob_index_cache_;
  std::unique_ptr<image_address_index> fallback_index_;

  image_entry* get_or_load_entry(const w1::rewind::image_record& image, std::string& error);
};

} // namespace w1replay
