#pragma once

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace w1::rewind {
struct module_record;
}

namespace w1replay {

class module_path_resolver {
public:
  virtual ~module_path_resolver() = default;
  virtual std::optional<std::string> resolve_module_path(const w1::rewind::module_record& module) const = 0;
  virtual std::optional<std::string> resolve_region_name(std::string_view recorded_name) const = 0;
};

class default_module_path_resolver final : public module_path_resolver {
public:
  default_module_path_resolver(std::vector<std::string> module_mappings, std::vector<std::string> module_dirs);

  std::optional<std::string> resolve_module_path(const w1::rewind::module_record& module) const override;
  std::optional<std::string> resolve_region_name(std::string_view recorded_name) const override;

private:
  std::optional<std::string> resolve_name(std::string_view name) const;

  std::vector<std::string> module_dirs_;
  std::unordered_map<std::string, std::string> overrides_;
};

std::unique_ptr<module_path_resolver> make_module_path_resolver(
    std::vector<std::string> module_mappings, std::vector<std::string> module_dirs
);

} // namespace w1replay
