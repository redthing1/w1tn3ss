#pragma once

#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include "image_bytes.hpp"
#include "w1rewind/format/trace_format.hpp"

namespace w1replay {

struct image_layout_identity {
  std::string identity;
  std::optional<uint32_t> age;
};

class image_layout_provider {
public:
  virtual ~image_layout_provider() = default;
  virtual bool build_layout(
      const w1::rewind::image_record& image, const w1::rewind::image_metadata_record* metadata, const std::string& path,
      image_layout& layout, image_layout_identity* identity, std::string& error
  ) = 0;
};

enum class image_layout_mode {
  trace,
  lief,
};

std::optional<image_layout_mode> parse_image_layout_mode(std::string_view value);
std::string_view format_image_layout_mode(image_layout_mode mode);

std::shared_ptr<image_layout_provider> make_layout_provider(image_layout_mode mode, std::string& error);

} // namespace w1replay
