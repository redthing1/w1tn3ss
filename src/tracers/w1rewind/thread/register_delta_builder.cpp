#include "register_delta_builder.hpp"

namespace w1rewind {

namespace {

std::vector<uint8_t> encode_register_value(uint64_t value, uint32_t byte_size, w1::rewind::endian byte_order) {
  std::vector<uint8_t> out(byte_size, 0);
  for (uint32_t i = 0; i < byte_size; ++i) {
    uint8_t byte = static_cast<uint8_t>((value >> (8u * i)) & 0xffu);
    if (byte_order == w1::rewind::endian::big && byte_size > 0) {
      out[byte_size - 1 - i] = byte;
    } else {
      out[i] = byte;
    }
  }
  return out;
}

} // namespace

std::vector<w1::rewind::reg_write_entry> capture_register_deltas(
    const register_schema& schema, const w1::util::register_state& regs, w1::rewind::endian byte_order,
    std::optional<w1::util::register_state>& last_regs
) {
  const auto& current = regs.get_register_map();
  const auto* previous = last_regs ? &last_regs->get_register_map() : nullptr;

  std::vector<w1::rewind::reg_write_entry> out;
  const auto& specs = schema.specs();
  out.reserve(specs.size());

  for (const auto& spec : specs) {
    if (spec.name.empty()) {
      continue;
    }
    auto current_it = current.find(spec.name);
    if (current_it == current.end()) {
      continue;
    }
    bool changed = true;
    if (previous) {
      auto previous_it = previous->find(spec.name);
      if (previous_it != previous->end() && previous_it->second == current_it->second) {
        changed = false;
      }
    }
    if (!changed) {
      continue;
    }

    w1::rewind::reg_write_entry entry{};
    uint32_t byte_size = (spec.bit_size + 7u) / 8u;
    if (byte_size == 0 || byte_size > sizeof(uint64_t)) {
      continue;
    }
    entry.ref_kind = w1::rewind::reg_ref_kind::reg_id;
    entry.reg_id = spec.reg_id;
    entry.byte_offset = 0;
    entry.byte_size = byte_size;
    entry.value = encode_register_value(current_it->second, byte_size, byte_order);
    out.push_back(std::move(entry));
  }

  last_regs = regs;
  return out;
}

std::vector<w1::rewind::reg_write_entry> capture_register_snapshot(
    const register_schema& schema, const w1::util::register_state& regs, w1::rewind::endian byte_order
) {
  std::vector<w1::rewind::reg_write_entry> out;
  const auto& current = regs.get_register_map();
  const auto& specs = schema.specs();
  out.reserve(specs.size());

  for (const auto& spec : specs) {
    if (spec.name.empty()) {
      continue;
    }
    auto current_it = current.find(spec.name);
    if (current_it == current.end()) {
      continue;
    }

    w1::rewind::reg_write_entry entry{};
    uint32_t byte_size = (spec.bit_size + 7u) / 8u;
    if (byte_size == 0 || byte_size > sizeof(uint64_t)) {
      continue;
    }
    entry.ref_kind = w1::rewind::reg_ref_kind::reg_id;
    entry.reg_id = spec.reg_id;
    entry.byte_offset = 0;
    entry.byte_size = byte_size;
    entry.value = encode_register_value(current_it->second, byte_size, byte_order);
    out.push_back(std::move(entry));
  }

  return out;
}

} // namespace w1rewind
