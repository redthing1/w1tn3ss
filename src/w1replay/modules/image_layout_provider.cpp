#include "image_layout_provider.hpp"

#include "lief_image_layout_provider.hpp"

namespace w1replay {

std::optional<image_layout_mode> parse_image_layout_mode(std::string_view value) {
  if (value == "trace") {
    return image_layout_mode::trace;
  }
  if (value == "lief") {
    return image_layout_mode::lief;
  }
  return std::nullopt;
}

std::string_view format_image_layout_mode(image_layout_mode mode) {
  switch (mode) {
  case image_layout_mode::trace:
    return "trace";
  case image_layout_mode::lief:
    return "lief";
  default:
    return "trace";
  }
}

std::shared_ptr<image_layout_provider> make_layout_provider(image_layout_mode mode, std::string& error) {
  error.clear();
  switch (mode) {
  case image_layout_mode::trace:
    return {};
  case image_layout_mode::lief:
    return make_lief_layout_provider(error);
  default:
    error = "unknown image layout mode";
    return {};
  }
}

} // namespace w1replay
