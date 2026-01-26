#pragma once

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace w1::rewind {
struct image_record;
}

namespace w1replay {

class image_path_resolver {
public:
  virtual ~image_path_resolver() = default;
  virtual std::optional<std::string> resolve_image_path(const w1::rewind::image_record& image) const = 0;
  virtual std::optional<std::string> resolve_region_name(std::string_view recorded_name) const = 0;
};

class default_image_path_resolver final : public image_path_resolver {
public:
  default_image_path_resolver(std::vector<std::string> image_mappings, std::vector<std::string> image_dirs);

  std::optional<std::string> resolve_image_path(const w1::rewind::image_record& image) const override;
  std::optional<std::string> resolve_region_name(std::string_view recorded_name) const override;

private:
  std::optional<std::string> resolve_name(std::string_view name) const;
  std::optional<std::string> resolve_override(std::string_view name) const;

  struct basename_override {
    std::string key;
    std::string path;
  };

  std::vector<std::string> image_dirs_;
  std::unordered_map<std::string, std::string> overrides_exact_;
  std::unordered_map<std::string, basename_override> overrides_basename_;
  std::unordered_set<std::string> ambiguous_basenames_;
};

std::unique_ptr<image_path_resolver> make_image_path_resolver(
    std::vector<std::string> image_mappings, std::vector<std::string> image_dirs
);

} // namespace w1replay
