#include "env_config.hpp"
#include <cstdlib>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <iostream>

namespace w1 {
namespace util {

env_config::env_config(const std::string& prefix) : prefix_(prefix) {
  if (!prefix_.empty() && prefix_.back() != '_') {
    prefix_ += "_";
  }
}

std::string env_config::build_env_name(const std::string& name) const { return prefix_ + name; }

std::string env_config::get_env_value(const std::string& name) const {
  const char* value = std::getenv(build_env_name(name).c_str());
  return value ? std::string(value) : std::string();
}

std::string env_config::to_lower(const std::string& str) const {
  std::string result = str;
  std::transform(result.begin(), result.end(), result.begin(), ::tolower);
  return result;
}

std::string env_config::trim(const std::string& str) const {
  size_t first = str.find_first_not_of(' ');
  if (std::string::npos == first) {
    return str;
  }
  size_t last = str.find_last_not_of(' ');
  return str.substr(first, (last - first + 1));
}

template <> std::string env_config::get<std::string>(const std::string& name, std::string default_value) const {
  std::string value = get_env_value(name);
  return value.empty() ? default_value : value;
}

template <> bool env_config::get<bool>(const std::string& name, bool default_value) const {
  std::string value = get_env_value(name);
  if (value.empty()) {
    return default_value;
  }

  std::string lower_value = to_lower(value);
  return (lower_value == "1" || lower_value == "true" || lower_value == "yes" || lower_value == "on");
}

template <> int env_config::get<int>(const std::string& name, int default_value) const {
  std::string value = get_env_value(name);
  if (value.empty()) {
    return default_value;
  }

  try {
    return std::stoi(value);
  } catch (const std::exception& e) {
    std::cerr << "Warning: Failed to parse " << build_env_name(name) << " as int: " << e.what() << ", using default"
              << std::endl;
    return default_value;
  }
}

template <> long env_config::get<long>(const std::string& name, long default_value) const {
  std::string value = get_env_value(name);
  if (value.empty()) {
    return default_value;
  }

  try {
    return std::stol(value);
  } catch (const std::exception& e) {
    std::cerr << "Warning: Failed to parse " << build_env_name(name) << " as long: " << e.what() << ", using default"
              << std::endl;
    return default_value;
  }
}

template <> uint32_t env_config::get<uint32_t>(const std::string& name, uint32_t default_value) const {
  std::string value = get_env_value(name);
  if (value.empty()) {
    return default_value;
  }

  try {
    return static_cast<uint32_t>(std::stoul(value));
  } catch (const std::exception& e) {
    std::cerr << "Warning: Failed to parse " << build_env_name(name) << " as uint32_t: " << e.what()
              << ", using default" << std::endl;
    return default_value;
  }
}

template <> uint64_t env_config::get<uint64_t>(const std::string& name, uint64_t default_value) const {
  std::string value = get_env_value(name);
  if (value.empty()) {
    return default_value;
  }

  try {
    return std::stoull(value);
  } catch (const std::exception& e) {
    std::cerr << "Warning: Failed to parse " << build_env_name(name) << " as uint64_t: " << e.what()
              << ", using default" << std::endl;
    return default_value;
  }
}

template <> float env_config::get<float>(const std::string& name, float default_value) const {
  std::string value = get_env_value(name);
  if (value.empty()) {
    return default_value;
  }

  try {
    return std::stof(value);
  } catch (const std::exception& e) {
    std::cerr << "Warning: Failed to parse " << build_env_name(name) << " as float: " << e.what() << ", using default"
              << std::endl;
    return default_value;
  }
}

template <> double env_config::get<double>(const std::string& name, double default_value) const {
  std::string value = get_env_value(name);
  if (value.empty()) {
    return default_value;
  }

  try {
    return std::stod(value);
  } catch (const std::exception& e) {
    std::cerr << "Warning: Failed to parse " << build_env_name(name) << " as double: " << e.what() << ", using default"
              << std::endl;
    return default_value;
  }
}

template <> size_t env_config::get<size_t>(const std::string& name, size_t default_value) const {
  std::string value = get_env_value(name);
  if (value.empty()) {
    return default_value;
  }

  try {
    return static_cast<size_t>(std::stoull(value));
  } catch (const std::exception& e) {
    std::cerr << "Warning: Failed to parse " << build_env_name(name) << " as size_t: " << e.what() << ", using default"
              << std::endl;
    return default_value;
  }
}

std::vector<std::string> env_config::get_list(const std::string& name, char delimiter) const {
  std::string value = get_env_value(name);
  std::vector<std::string> result;

  if (value.empty()) {
    return result;
  }

  std::stringstream ss(value);
  std::string item;

  while (std::getline(ss, item, delimiter)) {
    result.push_back(trim(item));
  }

  return result;
}

template <typename EnumType>
EnumType env_config::get_enum(
    const std::initializer_list<std::pair<const char*, EnumType>>& mapping, const std::string& name,
    EnumType default_value
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

  std::cerr << "Warning: Unknown value '" << value << "' for " << build_env_name(name) << ", using default"
            << std::endl;
  return default_value;
}

} // namespace util
} // namespace w1