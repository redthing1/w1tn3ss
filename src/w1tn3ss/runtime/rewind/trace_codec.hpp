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
    writer.write_u32(module.permissions);
    if (!writer.write_string(module.path)) {
      log.err("trace string too long", redlog::field("length", module.path.size()));
      return false;
    }
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
    if (!reader.read_u64(module.id) || !reader.read_u64(module.base) || !reader.read_u64(module.size) ||
        !reader.read_u32(module.permissions) || !reader.read_string(module.path)) {
      return false;
    }
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
  writer.write_u64(record.module_id);
  writer.write_u64(record.module_offset);
  writer.write_u32(record.size);
  writer.write_u32(record.flags);
  return true;
}

inline bool decode_instruction(trace_buffer_reader& reader, instruction_record& out) {
  return reader.read_u64(out.sequence) && reader.read_u64(out.thread_id) && reader.read_u64(out.module_id) &&
         reader.read_u64(out.module_offset) && reader.read_u32(out.size) && reader.read_u32(out.flags);
}

inline bool encode_block_definition(const block_definition_record& record, trace_buffer_writer& writer) {
  writer.write_u64(record.block_id);
  writer.write_u64(record.module_id);
  writer.write_u64(record.module_offset);
  writer.write_u32(record.size);
  return true;
}

inline bool decode_block_definition(trace_buffer_reader& reader, block_definition_record& out) {
  return reader.read_u64(out.block_id) && reader.read_u64(out.module_id) && reader.read_u64(out.module_offset) &&
         reader.read_u32(out.size);
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

inline bool encode_boundary(const boundary_record& record, trace_buffer_writer& writer, redlog::logger& log) {
  if (record.registers.size() > std::numeric_limits<uint16_t>::max()) {
    log.err("boundary register list too large", redlog::field("count", record.registers.size()));
    return false;
  }
  if (record.stack_window.size() > std::numeric_limits<uint32_t>::max()) {
    log.err("boundary stack window too large", redlog::field("size", record.stack_window.size()));
    return false;
  }
  writer.write_u64(record.boundary_id);
  writer.write_u64(record.sequence);
  writer.write_u64(record.thread_id);
  writer.write_u16(static_cast<uint16_t>(record.registers.size()));
  for (const auto& reg : record.registers) {
    writer.write_u16(reg.reg_id);
    writer.write_u64(reg.value);
  }
  writer.write_u32(static_cast<uint32_t>(record.stack_window.size()));
  if (!record.stack_window.empty()) {
    writer.write_bytes(record.stack_window.data(), record.stack_window.size());
  }
  if (!writer.write_string(record.reason)) {
    log.err("trace string too long", redlog::field("length", record.reason.size()));
    return false;
  }
  return true;
}

inline bool decode_boundary(trace_buffer_reader& reader, boundary_record& out) {
  uint16_t reg_count = 0;
  uint32_t stack_size = 0;
  if (!reader.read_u64(out.boundary_id) || !reader.read_u64(out.sequence) || !reader.read_u64(out.thread_id) ||
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
    if (!reader.read_bytes(out.stack_window, stack_size)) {
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
