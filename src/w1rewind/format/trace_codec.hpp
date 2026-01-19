#pragma once

#include <limits>

#include <redlog.hpp>

#include "trace_format.hpp"
#include "trace_io.hpp"

namespace w1::rewind {

inline bool encode_register_table(
    const register_table_record& record, trace_buffer_writer& writer, redlog::logger& log
) {
  if (record.names.size() > std::numeric_limits<uint16_t>::max()) {
    log.err("register table too large", redlog::field("count", record.names.size()));
    return false;
  }
  writer.write_u16(static_cast<uint16_t>(record.names.size()));
  for (const auto& name : record.names) {
    if (!writer.write_string(name)) {
      log.err("trace string too long", redlog::field("length", name.size()));
      return false;
    }
  }
  return true;
}

inline bool decode_register_table(trace_buffer_reader& reader, register_table_record& out) {
  uint16_t count = 0;
  if (!reader.read_u16(count)) {
    return false;
  }
  out.names.reserve(count);
  for (uint16_t i = 0; i < count; ++i) {
    std::string name;
    if (!reader.read_string(name)) {
      return false;
    }
    out.names.push_back(std::move(name));
  }
  return true;
}

inline bool encode_target_info(
    const target_info_record& record, trace_buffer_writer& writer, redlog::logger& log
) {
  if (!writer.write_string(record.os)) {
    log.err("trace string too long", redlog::field("length", record.os.size()));
    return false;
  }
  if (!writer.write_string(record.abi)) {
    log.err("trace string too long", redlog::field("length", record.abi.size()));
    return false;
  }
  if (!writer.write_string(record.cpu)) {
    log.err("trace string too long", redlog::field("length", record.cpu.size()));
    return false;
  }
  return true;
}

inline bool decode_target_info(trace_buffer_reader& reader, target_info_record& out) {
  if (!reader.read_string(out.os) || !reader.read_string(out.abi) || !reader.read_string(out.cpu)) {
    return false;
  }
  return true;
}

inline bool encode_register_spec(
    const register_spec_record& record, trace_buffer_writer& writer, redlog::logger& log
) {
  if (record.registers.size() > std::numeric_limits<uint16_t>::max()) {
    log.err("register spec list too large", redlog::field("count", record.registers.size()));
    return false;
  }
  writer.write_u16(static_cast<uint16_t>(record.registers.size()));
  for (const auto& reg : record.registers) {
    writer.write_u16(reg.reg_id);
    writer.write_u16(reg.bits);
    writer.write_u16(reg.flags);
    writer.write_u8(static_cast<uint8_t>(reg.reg_class));
    writer.write_u8(static_cast<uint8_t>(reg.value_kind));
    if (!writer.write_string(reg.name)) {
      log.err("trace string too long", redlog::field("length", reg.name.size()));
      return false;
    }
    if (!writer.write_string(reg.gdb_name)) {
      log.err("trace string too long", redlog::field("length", reg.gdb_name.size()));
      return false;
    }
  }
  return true;
}

inline bool decode_register_spec(trace_buffer_reader& reader, register_spec_record& out) {
  uint16_t count = 0;
  if (!reader.read_u16(count)) {
    return false;
  }
  out.registers.reserve(count);
  for (uint16_t i = 0; i < count; ++i) {
    register_spec spec{};
    uint8_t reg_class = 0;
    uint8_t value_kind = 0;
    if (!reader.read_u16(spec.reg_id) || !reader.read_u16(spec.bits) || !reader.read_u16(spec.flags) ||
        !reader.read_u8(reg_class) || !reader.read_u8(value_kind) || !reader.read_string(spec.name) ||
        !reader.read_string(spec.gdb_name)) {
      return false;
    }
    spec.reg_class = static_cast<register_class>(reg_class);
    spec.value_kind = static_cast<register_value_kind>(value_kind);
    out.registers.push_back(std::move(spec));
  }
  return true;
}

inline bool encode_module_table(const module_table_record& record, trace_buffer_writer& writer, redlog::logger& log) {
  if (record.modules.size() > std::numeric_limits<uint32_t>::max()) {
    log.err("module table too large", redlog::field("count", record.modules.size()));
    return false;
  }
  writer.write_u32(static_cast<uint32_t>(record.modules.size()));
  for (const auto& module : record.modules) {
    writer.write_u64(module.id);
    writer.write_u64(module.base);
    writer.write_u64(module.size);
    writer.write_u32(static_cast<uint32_t>(module.permissions));
    if (!writer.write_string(module.path)) {
      log.err("trace string too long", redlog::field("length", module.path.size()));
      return false;
    }
  }
  return true;
}

inline bool encode_memory_map(const memory_map_record& record, trace_buffer_writer& writer, redlog::logger& log) {
  if (record.regions.size() > std::numeric_limits<uint32_t>::max()) {
    log.err("memory map too large", redlog::field("count", record.regions.size()));
    return false;
  }
  writer.write_u32(static_cast<uint32_t>(record.regions.size()));
  for (const auto& region : record.regions) {
    writer.write_u64(region.base);
    writer.write_u64(region.size);
    writer.write_u32(static_cast<uint32_t>(region.permissions));
    writer.write_u64(region.image_id);
    if (!writer.write_string(region.name)) {
      log.err("trace string too long", redlog::field("length", region.name.size()));
      return false;
    }
  }
  return true;
}

inline bool decode_memory_map(trace_buffer_reader& reader, memory_map_record& out) {
  uint32_t count = 0;
  if (!reader.read_u32(count)) {
    return false;
  }
  out.regions.reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    memory_region_record region{};
    uint32_t perms = 0;
    if (!reader.read_u64(region.base) || !reader.read_u64(region.size) || !reader.read_u32(perms) ||
        !reader.read_u64(region.image_id) || !reader.read_string(region.name)) {
      return false;
    }
    region.permissions = static_cast<module_perm>(perms);
    out.regions.push_back(std::move(region));
  }
  return true;
}

inline bool decode_module_table(trace_buffer_reader& reader, module_table_record& out) {
  uint32_t count = 0;
  if (!reader.read_u32(count)) {
    return false;
  }
  out.modules.reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    module_record module{};
    uint32_t perms = 0;
    if (!reader.read_u64(module.id) || !reader.read_u64(module.base) || !reader.read_u64(module.size) ||
        !reader.read_u32(perms) || !reader.read_string(module.path)) {
      return false;
    }
    module.permissions = static_cast<module_perm>(perms);
    out.modules.push_back(std::move(module));
  }
  return true;
}

inline bool encode_thread_start(const thread_start_record& record, trace_buffer_writer& writer, redlog::logger& log) {
  writer.write_u64(record.thread_id);
  if (!writer.write_string(record.name)) {
    log.err("trace string too long", redlog::field("length", record.name.size()));
    return false;
  }
  return true;
}

inline bool decode_thread_start(trace_buffer_reader& reader, thread_start_record& out) {
  return reader.read_u64(out.thread_id) && reader.read_string(out.name);
}

inline bool encode_instruction(const instruction_record& record, trace_buffer_writer& writer) {
  writer.write_u64(record.sequence);
  writer.write_u64(record.thread_id);
  writer.write_u64(record.address);
  writer.write_u32(record.size);
  writer.write_u32(record.flags);
  return true;
}

inline bool decode_instruction(trace_buffer_reader& reader, instruction_record& out) {
  return reader.read_u64(out.sequence) && reader.read_u64(out.thread_id) && reader.read_u64(out.address) &&
         reader.read_u32(out.size) && reader.read_u32(out.flags);
}

inline bool encode_block_definition(const block_definition_record& record, trace_buffer_writer& writer) {
  writer.write_u64(record.block_id);
  writer.write_u64(record.address);
  writer.write_u32(record.size);
  writer.write_u32(record.flags);
  return true;
}

inline bool decode_block_definition(trace_buffer_reader& reader, block_definition_record& out) {
  return reader.read_u64(out.block_id) && reader.read_u64(out.address) && reader.read_u32(out.size) &&
         reader.read_u32(out.flags);
}

inline bool encode_block_exec(const block_exec_record& record, trace_buffer_writer& writer) {
  writer.write_u64(record.sequence);
  writer.write_u64(record.thread_id);
  writer.write_u64(record.block_id);
  return true;
}

inline bool decode_block_exec(trace_buffer_reader& reader, block_exec_record& out) {
  return reader.read_u64(out.sequence) && reader.read_u64(out.thread_id) && reader.read_u64(out.block_id);
}

inline bool encode_register_deltas(
    const register_delta_record& record, trace_buffer_writer& writer, redlog::logger& log
) {
  if (record.deltas.size() > std::numeric_limits<uint16_t>::max()) {
    log.err("register delta list too large", redlog::field("count", record.deltas.size()));
    return false;
  }
  writer.write_u64(record.sequence);
  writer.write_u64(record.thread_id);
  writer.write_u16(static_cast<uint16_t>(record.deltas.size()));
  for (const auto& delta : record.deltas) {
    writer.write_u16(delta.reg_id);
    writer.write_u64(delta.value);
  }
  return true;
}

inline bool decode_register_deltas(trace_buffer_reader& reader, register_delta_record& out) {
  uint16_t count = 0;
  if (!reader.read_u64(out.sequence) || !reader.read_u64(out.thread_id) || !reader.read_u16(count)) {
    return false;
  }
  out.deltas.reserve(count);
  for (uint16_t i = 0; i < count; ++i) {
    register_delta delta{};
    if (!reader.read_u16(delta.reg_id) || !reader.read_u64(delta.value)) {
      return false;
    }
    out.deltas.push_back(delta);
  }
  return true;
}

inline bool encode_register_bytes(
    const register_bytes_record& record, trace_buffer_writer& writer, redlog::logger& log
) {
  if (record.entries.size() > std::numeric_limits<uint16_t>::max()) {
    log.err("register bytes entry list too large", redlog::field("count", record.entries.size()));
    return false;
  }
  if (record.data.size() > std::numeric_limits<uint32_t>::max()) {
    log.err("register bytes data too large", redlog::field("size", record.data.size()));
    return false;
  }
  writer.write_u64(record.sequence);
  writer.write_u64(record.thread_id);
  writer.write_u16(static_cast<uint16_t>(record.entries.size()));
  for (const auto& entry : record.entries) {
    writer.write_u16(entry.reg_id);
    writer.write_u32(entry.offset);
    writer.write_u16(entry.size);
  }
  writer.write_u32(static_cast<uint32_t>(record.data.size()));
  if (!record.data.empty()) {
    writer.write_bytes(record.data.data(), record.data.size());
  }
  return true;
}

inline bool decode_register_bytes(trace_buffer_reader& reader, register_bytes_record& out) {
  uint16_t count = 0;
  uint32_t data_size = 0;
  if (!reader.read_u64(out.sequence) || !reader.read_u64(out.thread_id) || !reader.read_u16(count)) {
    return false;
  }
  out.entries.reserve(count);
  for (uint16_t i = 0; i < count; ++i) {
    register_bytes_entry entry{};
    if (!reader.read_u16(entry.reg_id) || !reader.read_u32(entry.offset) || !reader.read_u16(entry.size)) {
      return false;
    }
    out.entries.push_back(entry);
  }
  if (!reader.read_u32(data_size)) {
    return false;
  }
  if (data_size > 0) {
    if (!reader.read_bytes(out.data, data_size)) {
      return false;
    }
  }
  return true;
}

inline bool encode_memory_access(
    const memory_access_record& record, trace_buffer_writer& writer, redlog::logger& log
) {
  if (record.data.size() > std::numeric_limits<uint32_t>::max()) {
    log.err("memory record data too large", redlog::field("size", record.data.size()));
    return false;
  }
  writer.write_u64(record.sequence);
  writer.write_u64(record.thread_id);
  writer.write_u8(static_cast<uint8_t>(record.kind));
  writer.write_u8(record.value_known ? 1 : 0);
  writer.write_u8(record.value_truncated ? 1 : 0);
  writer.write_u8(0);
  writer.write_u64(record.address);
  writer.write_u32(record.size);
  writer.write_u32(static_cast<uint32_t>(record.data.size()));
  if (!record.data.empty()) {
    writer.write_bytes(record.data.data(), record.data.size());
  }
  return true;
}

inline bool decode_memory_access(trace_buffer_reader& reader, memory_access_record& out) {
  uint8_t kind = 0;
  uint8_t value_known = 0;
  uint8_t value_truncated = 0;
  uint8_t reserved = 0;
  uint32_t data_size = 0;
  if (!reader.read_u64(out.sequence) || !reader.read_u64(out.thread_id) || !reader.read_u8(kind) ||
      !reader.read_u8(value_known) || !reader.read_u8(value_truncated) || !reader.read_u8(reserved) ||
      !reader.read_u64(out.address) || !reader.read_u32(out.size) || !reader.read_u32(data_size)) {
    return false;
  }
  out.kind = static_cast<memory_access_kind>(kind);
  out.value_known = value_known != 0;
  out.value_truncated = value_truncated != 0;
  (void)reserved;
  if (data_size > 0) {
    if (!reader.read_bytes(out.data, data_size)) {
      return false;
    }
  }
  return true;
}

inline bool encode_snapshot(const snapshot_record& record, trace_buffer_writer& writer, redlog::logger& log) {
  if (record.registers.size() > std::numeric_limits<uint16_t>::max()) {
    log.err("snapshot register list too large", redlog::field("count", record.registers.size()));
    return false;
  }
  if (record.stack_snapshot.size() > std::numeric_limits<uint32_t>::max()) {
    log.err("snapshot stack slice too large", redlog::field("size", record.stack_snapshot.size()));
    return false;
  }
  writer.write_u64(record.snapshot_id);
  writer.write_u64(record.sequence);
  writer.write_u64(record.thread_id);
  writer.write_u16(static_cast<uint16_t>(record.registers.size()));
  for (const auto& reg : record.registers) {
    writer.write_u16(reg.reg_id);
    writer.write_u64(reg.value);
  }
  writer.write_u32(static_cast<uint32_t>(record.stack_snapshot.size()));
  if (!record.stack_snapshot.empty()) {
    writer.write_bytes(record.stack_snapshot.data(), record.stack_snapshot.size());
  }
  if (!writer.write_string(record.reason)) {
    log.err("trace string too long", redlog::field("length", record.reason.size()));
    return false;
  }
  return true;
}

inline bool decode_snapshot(trace_buffer_reader& reader, snapshot_record& out) {
  uint16_t reg_count = 0;
  uint32_t stack_size = 0;
  if (!reader.read_u64(out.snapshot_id) || !reader.read_u64(out.sequence) || !reader.read_u64(out.thread_id) ||
      !reader.read_u16(reg_count)) {
    return false;
  }
  out.registers.reserve(reg_count);
  for (uint16_t i = 0; i < reg_count; ++i) {
    register_delta delta{};
    if (!reader.read_u16(delta.reg_id) || !reader.read_u64(delta.value)) {
      return false;
    }
    out.registers.push_back(delta);
  }
  if (!reader.read_u32(stack_size)) {
    return false;
  }
  if (stack_size > 0) {
    if (!reader.read_bytes(out.stack_snapshot, stack_size)) {
      return false;
    }
  }
  if (!reader.read_string(out.reason)) {
    return false;
  }
  return true;
}

inline bool encode_thread_end(const thread_end_record& record, trace_buffer_writer& writer) {
  writer.write_u64(record.thread_id);
  return true;
}

inline bool decode_thread_end(trace_buffer_reader& reader, thread_end_record& out) {
  return reader.read_u64(out.thread_id);
}

} // namespace w1::rewind
