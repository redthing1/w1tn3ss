#pragma once

#include <optional>

#include "metadata_provider.hpp"
#include "w1rewind/replay/replay_context.hpp"

namespace w1replay {

class trace_image_metadata_provider final : public image_metadata_provider {
public:
  explicit trace_image_metadata_provider(const w1::rewind::replay_context* context);

  std::optional<std::string> image_uuid(const w1::rewind::image_record& image, std::string& error) override;
  std::optional<macho_header_info> macho_header(const w1::rewind::image_record& image, std::string& error) override;
  std::vector<macho_segment_info> macho_segments(
      const w1::rewind::image_record& image, std::string& error
  ) override;

private:
  const w1::rewind::replay_context* context_ = nullptr;
};

} // namespace w1replay
