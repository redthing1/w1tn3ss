#pragma once

#include <initializer_list>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

namespace w1::util {

class env_config {
public:
  explicit env_config(const std::string& prefix = "");

  template <typename T> T get(const std::string& name, T default_value) const;

  std::vector<std::string> get_list(const std::string& name, char delimiter = ',') const;

  template <typename enum_type>
  enum_type get_enum(
      const std::initializer_list<std::pair<const char*, enum_type>>& mapping, const std::string& name,
      enum_type default_value
  ) const;

private:
  std::string prefix_;
  std::string build_env_name(const std::string& name) const;
  std::string get_env_value(const std::string& name) const;
  std::string to_lower(const std::string& value) const;
  std::string trim(const std::string& value) const;
};

template <typename enum_type>
enum_type env_config::get_enum(
    const std::initializer_list<std::pair<const char*, enum_type>>& mapping, const std::string& name,
    enum_type default_value
) const {
  std::string value = get_env_value(name);
  if (value.empty()) {
    return default_value;
  }

  std::string lower_value = to_lower(value);

  for (const auto& pair : mapping) {
    if (to_lower(pair.first) == lower_value) {
      return pair.second;
    }
  }

  std::cerr << "warning: unknown value '" << value << "' for " << build_env_name(name)
            << ", using default\n";
  return default_value;
}

} // namespace w1::util
