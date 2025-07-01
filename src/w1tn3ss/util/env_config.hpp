#pragma once

#include <string>
#include <vector>
#include <initializer_list>
#include <utility>

namespace w1 {
namespace util {

class env_config {
public:
  explicit env_config(const std::string& prefix = "");

  template <typename T> T get(const std::string& name, T default_value) const;

  std::vector<std::string> get_list(const std::string& name, char delimiter = ',') const;

  template <typename EnumType>
  EnumType get_enum(
      const std::initializer_list<std::pair<const char*, EnumType>>& mapping, const std::string& name,
      EnumType default_value
  ) const;

private:
  std::string prefix_;
  std::string build_env_name(const std::string& name) const;
  std::string get_env_value(const std::string& name) const;
  std::string to_lower(const std::string& str) const;
  std::string trim(const std::string& str) const;
};

} // namespace util
} // namespace w1