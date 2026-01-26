#pragma once

#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "w1rewind/format/trace_format.hpp"

namespace w1::util {
class register_state;
}

namespace w1rewind {

class register_schema {
public:
  void clear();
  void set_specs(std::vector<w1::rewind::register_spec> specs);
  bool empty() const { return specs_.empty(); }

  const std::vector<std::string>& names() const { return names_; }
  const std::vector<w1::rewind::register_spec>& specs() const { return specs_; }
  const w1::rewind::register_spec* find_spec(std::string_view name) const;
  const w1::rewind::register_spec* find_spec_by_flag(uint16_t flag) const;
  bool covers_registers(const w1::util::register_state& regs, std::string& error) const;
  bool has_sizing() const;

private:
  void rebuild_index();

  std::vector<std::string> names_;
  std::vector<w1::rewind::register_spec> specs_;
  std::unordered_map<std::string_view, size_t, std::hash<std::string_view>, std::equal_to<>> name_to_index_;
};

} // namespace w1rewind
