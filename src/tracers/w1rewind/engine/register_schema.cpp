#include "register_schema.hpp"

#include <algorithm>

#include "w1runtime/register_capture.hpp"

namespace w1rewind {

void register_schema::clear() {
  names_.clear();
  specs_.clear();
  name_to_index_.clear();
}

void register_schema::set_specs(std::vector<w1::rewind::register_spec> specs) {
  specs_ = std::move(specs);
  names_.clear();
  names_.reserve(specs_.size());
  for (const auto& spec : specs_) {
    names_.push_back(spec.name);
  }
  rebuild_index();
}

const w1::rewind::register_spec* register_schema::find_spec(std::string_view name) const {
  auto it = name_to_index_.find(name);
  if (it == name_to_index_.end()) {
    return nullptr;
  }
  if (it->second >= specs_.size()) {
    return nullptr;
  }
  return &specs_[it->second];
}

const w1::rewind::register_spec* register_schema::find_spec_by_flag(uint16_t flag) const {
  if (flag == 0) {
    return nullptr;
  }
  for (const auto& spec : specs_) {
    if ((spec.flags & flag) != 0) {
      return &spec;
    }
  }
  return nullptr;
}

bool register_schema::covers_registers(const w1::util::register_state& regs, std::string& error) const {
  error.clear();
  auto names = regs.get_register_names();
  for (const auto& name : names) {
    if (!find_spec(name)) {
      error = "register schema missing register: " + name;
      return false;
    }
  }
  return true;
}

void register_schema::rebuild_index() {
  name_to_index_.clear();
  name_to_index_.reserve(specs_.size() * 2);
  for (size_t i = 0; i < specs_.size(); ++i) {
    const auto& spec = specs_[i];
    if (!spec.name.empty()) {
      name_to_index_.emplace(std::string_view(spec.name), i);
    }
    if (!spec.gdb_name.empty()) {
      name_to_index_.emplace(std::string_view(spec.gdb_name), i);
    }
  }
}

bool register_schema::has_sizing() const {
  if (specs_.empty()) {
    return false;
  }
  for (const auto& spec : specs_) {
    if (spec.bit_size == 0) {
      return false;
    }
  }
  return true;
}

} // namespace w1rewind
