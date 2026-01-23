#include "register_delta_builder.hpp"

namespace w1rewind {

std::vector<w1::rewind::register_delta> capture_register_deltas(
    const register_schema& schema, const w1::util::register_state& regs,
    std::optional<w1::util::register_state>& last_regs
) {
  const auto& current = regs.get_register_map();
  const auto* previous = last_regs ? &last_regs->get_register_map() : nullptr;

  std::vector<w1::rewind::register_delta> out;
  const auto& names = schema.names();
  out.reserve(names.size());

  for (size_t i = 0; i < names.size(); ++i) {
    const auto& name = names[i];
    auto current_it = current.find(name);
    if (current_it == current.end()) {
      continue;
    }
    bool changed = true;
    if (previous) {
      auto previous_it = previous->find(name);
      if (previous_it != previous->end() && previous_it->second == current_it->second) {
        changed = false;
      }
    }
    if (!changed) {
      continue;
    }

    w1::rewind::register_delta delta{};
    delta.reg_id = static_cast<uint16_t>(i);
    delta.value = current_it->second;
    out.push_back(delta);
  }

  last_regs = regs;
  return out;
}

std::vector<w1::rewind::register_delta> capture_register_snapshot(
    const register_schema& schema, const w1::util::register_state& regs
) {
  std::vector<w1::rewind::register_delta> out;
  const auto& current = regs.get_register_map();
  const auto& names = schema.names();
  out.reserve(names.size());

  for (size_t i = 0; i < names.size(); ++i) {
    const auto& name = names[i];
    auto current_it = current.find(name);
    if (current_it == current.end()) {
      continue;
    }

    w1::rewind::register_delta delta{};
    delta.reg_id = static_cast<uint16_t>(i);
    delta.value = current_it->second;
    out.push_back(delta);
  }

  return out;
}

} // namespace w1rewind
