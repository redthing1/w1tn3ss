#pragma once

#include <limits>

#include <redlog.hpp>

#include "trace_format.hpp"
#include "trace_io.hpp"

namespace w1::rewind {

inline bool write_string_checked(trace_buffer_writer& writer, std::string_view value, redlog::logger& log) {
  if (!writer.write_string(value)) {
    log.err("trace string too long", redlog::field("length", value.size()));
    return false;
  }
  return true;
}

inline bool encode_string_map(
    const std::vector<std::pair<std::string, std::string>>& attrs, trace_buffer_writer& writer, redlog::logger& log
) {
  if (attrs.size() > std::numeric_limits<uint32_t>::max()) {
    log.err("attribute map too large", redlog::field("count", attrs.size()));
    return false;
  }
  writer.write_u32(static_cast<uint32_t>(attrs.size()));
  for (const auto& [key, value] : attrs) {
    if (!write_string_checked(writer, key, log) || !write_string_checked(writer, value, log)) {
      return false;
    }
  }
  return true;
}

inline bool decode_string_map(trace_buffer_reader& reader, std::vector<std::pair<std::string, std::string>>& out) {
  uint32_t count = 0;
  if (!reader.read_u32(count)) {
    return false;
  }
  out.clear();
  out.reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    std::string key;
    std::string value;
    if (!reader.read_string(key) || !reader.read_string(value)) {
      return false;
    }
    out.emplace_back(std::move(key), std::move(value));
  }
  return true;
}

inline bool encode_record_type_dictionary(
    const record_type_dictionary_record& record, trace_buffer_writer& writer, redlog::logger& log
) {
  if (record.entries.size() > std::numeric_limits<uint32_t>::max()) {
    log.err("record type dictionary too large", redlog::field("count", record.entries.size()));
    return false;
  }
  writer.write_u32(static_cast<uint32_t>(record.entries.size()));
  for (const auto& entry : record.entries) {
    writer.write_u32(entry.type_id);
    if (!write_string_checked(writer, entry.name, log)) {
      return false;
    }
  }
  return true;
}

inline bool decode_record_type_dictionary(trace_buffer_reader& reader, record_type_dictionary_record& out) {
  uint32_t count = 0;
  if (!reader.read_u32(count)) {
    return false;
  }
  out.entries.clear();
  out.entries.reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    record_type_dictionary_entry entry{};
    if (!reader.read_u32(entry.type_id) || !reader.read_string(entry.name)) {
      return false;
    }
    out.entries.push_back(std::move(entry));
  }
  return true;
}

inline bool encode_arch_descriptor(
    const arch_descriptor_record& record, trace_buffer_writer& writer, redlog::logger& log
) {
  if (!write_string_checked(writer, record.arch_id, log)) {
    return false;
  }
  writer.write_u8(static_cast<uint8_t>(record.byte_order));
  writer.write_u16(record.pointer_bits);
  writer.write_u16(record.address_bits);
  if (record.modes.size() > std::numeric_limits<uint32_t>::max()) {
    log.err("arch mode list too large", redlog::field("count", record.modes.size()));
    return false;
  }
  writer.write_u32(static_cast<uint32_t>(record.modes.size()));
  for (const auto& mode : record.modes) {
    writer.write_u16(mode.mode_id);
    if (!write_string_checked(writer, mode.name, log)) {
      return false;
    }
  }
  if (!write_string_checked(writer, record.gdb_arch, log)) {
    return false;
  }
  if (!write_string_checked(writer, record.gdb_feature, log)) {
    return false;
  }
  return true;
}

inline bool decode_arch_descriptor(trace_buffer_reader& reader, arch_descriptor_record& out) {
  if (!reader.read_string(out.arch_id)) {
    return false;
  }
  uint8_t order = 0;
  if (!reader.read_u8(order)) {
    return false;
  }
  out.byte_order = static_cast<endian>(order);
  if (!reader.read_u16(out.pointer_bits) || !reader.read_u16(out.address_bits)) {
    return false;
  }
  uint32_t mode_count = 0;
  if (!reader.read_u32(mode_count)) {
    return false;
  }
  out.modes.clear();
  out.modes.reserve(mode_count);
  for (uint32_t i = 0; i < mode_count; ++i) {
    arch_mode_entry mode{};
    if (!reader.read_u16(mode.mode_id) || !reader.read_string(mode.name)) {
      return false;
    }
    out.modes.push_back(std::move(mode));
  }
  if (!reader.read_string(out.gdb_arch) || !reader.read_string(out.gdb_feature)) {
    return false;
  }
  return true;
}

inline bool encode_environment(const environment_record& record, trace_buffer_writer& writer, redlog::logger& log) {
  if (!write_string_checked(writer, record.os_id, log)) {
    return false;
  }
  if (!write_string_checked(writer, record.abi, log)) {
    return false;
  }
  if (!write_string_checked(writer, record.cpu, log)) {
    return false;
  }
  if (!write_string_checked(writer, record.hostname, log)) {
    return false;
  }
  writer.write_u64(record.pid);
  if (!encode_string_map(record.attrs, writer, log)) {
    return false;
  }
  return true;
}

inline bool decode_environment(trace_buffer_reader& reader, environment_record& out) {
  if (!reader.read_string(out.os_id) || !reader.read_string(out.abi) || !reader.read_string(out.cpu) ||
      !reader.read_string(out.hostname) || !reader.read_u64(out.pid)) {
    return false;
  }
  if (!decode_string_map(reader, out.attrs)) {
    return false;
  }
  return true;
}

inline bool encode_address_space(const address_space_record& record, trace_buffer_writer& writer, redlog::logger& log) {
  writer.write_u32(record.space_id);
  if (!write_string_checked(writer, record.name, log)) {
    return false;
  }
  writer.write_u16(record.address_bits);
  writer.write_u8(static_cast<uint8_t>(record.byte_order));
  writer.write_u8(record.flags);
  return true;
}

inline bool decode_address_space(trace_buffer_reader& reader, address_space_record& out) {
  uint8_t order = 0;
  if (!reader.read_u32(out.space_id) || !reader.read_string(out.name) || !reader.read_u16(out.address_bits) ||
      !reader.read_u8(order) || !reader.read_u8(out.flags)) {
    return false;
  }
  out.byte_order = static_cast<endian>(order);
  return true;
}

inline bool encode_register_file(const register_file_record& record, trace_buffer_writer& writer, redlog::logger& log) {
  writer.write_u32(record.regfile_id);
  if (!write_string_checked(writer, record.name, log)) {
    return false;
  }
  if (record.registers.size() > std::numeric_limits<uint32_t>::max()) {
    log.err("register file too large", redlog::field("count", record.registers.size()));
    return false;
  }
  writer.write_u32(static_cast<uint32_t>(record.registers.size()));
  for (const auto& reg : record.registers) {
    writer.write_u32(reg.reg_id);
    if (!write_string_checked(writer, reg.name, log)) {
      return false;
    }
    writer.write_u16(reg.bit_size);
    writer.write_u16(reg.flags);
    if (!write_string_checked(writer, reg.gdb_name, log)) {
      return false;
    }
    writer.write_u32(reg.dwarf_regnum);
    writer.write_u32(reg.gcc_regnum);
  }
  return true;
}

inline bool decode_register_file(trace_buffer_reader& reader, register_file_record& out) {
  uint32_t count = 0;
  if (!reader.read_u32(out.regfile_id) || !reader.read_string(out.name) || !reader.read_u32(count)) {
    return false;
  }
  out.registers.clear();
  out.registers.reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    register_spec reg{};
    if (!reader.read_u32(reg.reg_id) || !reader.read_string(reg.name) || !reader.read_u16(reg.bit_size) ||
        !reader.read_u16(reg.flags) || !reader.read_string(reg.gdb_name) || !reader.read_u32(reg.dwarf_regnum) ||
        !reader.read_u32(reg.gcc_regnum)) {
      return false;
    }
    out.registers.push_back(std::move(reg));
  }
  return true;
}

inline bool encode_image(const image_record& record, trace_buffer_writer& writer, redlog::logger& log) {
  writer.write_u64(record.image_id);
  writer.write_u32(record.flags);
  if (!write_string_checked(writer, record.kind, log)) {
    return false;
  }
  if (!write_string_checked(writer, record.name, log)) {
    return false;
  }
  if (!write_string_checked(writer, record.identity, log)) {
    return false;
  }
  if (!write_string_checked(writer, record.path, log)) {
    return false;
  }
  if (!encode_string_map(record.attrs, writer, log)) {
    return false;
  }
  return true;
}

inline bool decode_image(trace_buffer_reader& reader, image_record& out) {
  if (!reader.read_u64(out.image_id) || !reader.read_u32(out.flags) || !reader.read_string(out.kind) ||
      !reader.read_string(out.name) || !reader.read_string(out.identity) || !reader.read_string(out.path)) {
    return false;
  }
  if (!decode_string_map(reader, out.attrs)) {
    return false;
  }
  return true;
}

inline bool encode_image_metadata(
    const image_metadata_record& record, trace_buffer_writer& writer, redlog::logger& log
) {
  writer.write_u64(record.image_id);
  writer.write_u32(record.flags);
  if (!write_string_checked(writer, record.format, log)) {
    return false;
  }
  if (!write_string_checked(writer, record.uuid, log)) {
    return false;
  }
  writer.write_u32(record.identity_age);
  writer.write_u64(record.entry_point);
  writer.write_u64(record.link_base);
  writer.write_u32(record.macho_header.magic);
  writer.write_u32(record.macho_header.cputype);
  writer.write_u32(record.macho_header.cpusubtype);
  writer.write_u32(record.macho_header.filetype);

  if (record.segments.size() > std::numeric_limits<uint32_t>::max()) {
    log.err("image metadata has too many segments", redlog::field("count", record.segments.size()));
    return false;
  }
  writer.write_u32(static_cast<uint32_t>(record.segments.size()));
  for (const auto& segment : record.segments) {
    if (!write_string_checked(writer, segment.name, log)) {
      return false;
    }
    writer.write_u64(segment.vmaddr);
    writer.write_u64(segment.vmsize);
    writer.write_u64(segment.fileoff);
    writer.write_u64(segment.filesize);
    writer.write_u32(segment.maxprot);
  }
  return true;
}

inline bool decode_image_metadata(trace_buffer_reader& reader, image_metadata_record& out) {
  if (!reader.read_u64(out.image_id) || !reader.read_u32(out.flags) || !reader.read_string(out.format) ||
      !reader.read_string(out.uuid) || !reader.read_u32(out.identity_age) || !reader.read_u64(out.entry_point) ||
      !reader.read_u64(out.link_base) || !reader.read_u32(out.macho_header.magic) ||
      !reader.read_u32(out.macho_header.cputype) || !reader.read_u32(out.macho_header.cpusubtype) ||
      !reader.read_u32(out.macho_header.filetype)) {
    return false;
  }
  uint32_t count = 0;
  if (!reader.read_u32(count)) {
    return false;
  }
  out.segments.clear();
  out.segments.reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    image_segment_record segment{};
    if (!reader.read_string(segment.name) || !reader.read_u64(segment.vmaddr) || !reader.read_u64(segment.vmsize) ||
        !reader.read_u64(segment.fileoff) || !reader.read_u64(segment.filesize) || !reader.read_u32(segment.maxprot)) {
      return false;
    }
    out.segments.push_back(std::move(segment));
  }
  return true;
}

inline bool encode_image_blob(const image_blob_record& record, trace_buffer_writer& writer, redlog::logger& log) {
  writer.write_u64(record.image_id);
  writer.write_u64(record.offset);
  if (record.data.size() > std::numeric_limits<uint32_t>::max()) {
    log.err("image blob too large", redlog::field("size", record.data.size()));
    return false;
  }
  writer.write_u32(static_cast<uint32_t>(record.data.size()));
  if (!record.data.empty()) {
    writer.write_bytes(record.data.data(), record.data.size());
  }
  return true;
}

inline bool decode_image_blob(trace_buffer_reader& reader, image_blob_record& out) {
  uint32_t size = 0;
  if (!reader.read_u64(out.image_id) || !reader.read_u64(out.offset) || !reader.read_u32(size)) {
    return false;
  }
  if (size > 0) {
    if (!reader.read_bytes(out.data, size)) {
      return false;
    }
  } else {
    out.data.clear();
  }
  return true;
}

inline bool encode_mapping(const mapping_record& record, trace_buffer_writer& writer, redlog::logger& log) {
  writer.write_u8(static_cast<uint8_t>(record.kind));
  writer.write_u32(record.space_id);
  writer.write_u64(record.base);
  writer.write_u64(record.size);
  writer.write_u8(static_cast<uint8_t>(record.perms));
  writer.write_u8(record.flags);
  writer.write_u64(record.image_id);
  writer.write_u64(record.image_offset);
  if (!write_string_checked(writer, record.name, log)) {
    return false;
  }
  return true;
}

inline bool decode_mapping(trace_buffer_reader& reader, mapping_record& out) {
  uint8_t kind = 0;
  uint8_t perms = 0;
  if (!reader.read_u8(kind) || !reader.read_u32(out.space_id) || !reader.read_u64(out.base) ||
      !reader.read_u64(out.size) || !reader.read_u8(perms) || !reader.read_u8(out.flags) ||
      !reader.read_u64(out.image_id) || !reader.read_u64(out.image_offset) || !reader.read_string(out.name)) {
    return false;
  }
  out.kind = static_cast<mapping_event_kind>(kind);
  out.perms = static_cast<mapping_perm>(perms);
  return true;
}

inline bool encode_thread_start(const thread_start_record& record, trace_buffer_writer& writer, redlog::logger& log) {
  writer.write_u64(record.thread_id);
  if (!write_string_checked(writer, record.name, log)) {
    return false;
  }
  return true;
}

inline bool decode_thread_start(trace_buffer_reader& reader, thread_start_record& out) {
  return reader.read_u64(out.thread_id) && reader.read_string(out.name);
}

inline bool encode_thread_end(const thread_end_record& record, trace_buffer_writer& writer) {
  writer.write_u64(record.thread_id);
  return true;
}

inline bool decode_thread_end(trace_buffer_reader& reader, thread_end_record& out) {
  return reader.read_u64(out.thread_id);
}

inline bool encode_flow_instruction(const flow_instruction_record& record, trace_buffer_writer& writer) {
  writer.write_u64(record.thread_id);
  writer.write_u64(record.sequence);
  writer.write_u32(record.space_id);
  writer.write_u16(record.mode_id);
  writer.write_u16(record.flags);
  writer.write_u64(record.address);
  writer.write_u32(record.size);
  return true;
}

inline bool decode_flow_instruction(trace_buffer_reader& reader, flow_instruction_record& out) {
  return reader.read_u64(out.thread_id) && reader.read_u64(out.sequence) && reader.read_u32(out.space_id) &&
         reader.read_u16(out.mode_id) && reader.read_u16(out.flags) && reader.read_u64(out.address) &&
         reader.read_u32(out.size);
}

inline bool encode_block_definition(const block_definition_record& record, trace_buffer_writer& writer) {
  writer.write_u64(record.block_id);
  writer.write_u32(record.space_id);
  writer.write_u16(record.mode_id);
  writer.write_u16(record.flags);
  writer.write_u64(record.address);
  writer.write_u32(record.size);
  return true;
}

inline bool decode_block_definition(trace_buffer_reader& reader, block_definition_record& out) {
  return reader.read_u64(out.block_id) && reader.read_u32(out.space_id) && reader.read_u16(out.mode_id) &&
         reader.read_u16(out.flags) && reader.read_u64(out.address) && reader.read_u32(out.size);
}

inline bool encode_block_exec(const block_exec_record& record, trace_buffer_writer& writer) {
  writer.write_u64(record.thread_id);
  writer.write_u64(record.sequence);
  writer.write_u64(record.block_id);
  return true;
}

inline bool decode_block_exec(trace_buffer_reader& reader, block_exec_record& out) {
  return reader.read_u64(out.thread_id) && reader.read_u64(out.sequence) && reader.read_u64(out.block_id);
}

inline bool encode_reg_write_entry(const reg_write_entry& entry, trace_buffer_writer& writer, redlog::logger& log) {
  writer.write_u8(static_cast<uint8_t>(entry.ref_kind));
  writer.write_u8(entry.reserved);
  writer.write_u32(entry.byte_offset);
  writer.write_u32(entry.byte_size);
  if (entry.ref_kind == reg_ref_kind::reg_id) {
    writer.write_u32(entry.reg_id);
  } else {
    if (!write_string_checked(writer, entry.reg_name, log)) {
      return false;
    }
  }
  if (entry.value.size() != entry.byte_size) {
    log.err("register write size mismatch", redlog::field("size", entry.value.size()));
    return false;
  }
  if (!entry.value.empty()) {
    writer.write_bytes(entry.value.data(), entry.value.size());
  }
  return true;
}

inline bool decode_reg_write_entry(trace_buffer_reader& reader, reg_write_entry& entry) {
  uint8_t ref_kind = 0;
  if (!reader.read_u8(ref_kind) || !reader.read_u8(entry.reserved) || !reader.read_u32(entry.byte_offset) ||
      !reader.read_u32(entry.byte_size)) {
    return false;
  }
  entry.ref_kind = static_cast<reg_ref_kind>(ref_kind);
  if (entry.ref_kind == reg_ref_kind::reg_id) {
    if (!reader.read_u32(entry.reg_id)) {
      return false;
    }
  } else {
    if (!reader.read_string(entry.reg_name)) {
      return false;
    }
  }
  if (entry.byte_size > 0) {
    if (!reader.read_bytes(entry.value, entry.byte_size)) {
      return false;
    }
  }
  return true;
}

inline bool encode_reg_write(const reg_write_record& record, trace_buffer_writer& writer, redlog::logger& log) {
  writer.write_u64(record.thread_id);
  writer.write_u64(record.sequence);
  writer.write_u32(record.regfile_id);
  if (record.entries.size() > std::numeric_limits<uint32_t>::max()) {
    log.err("register write entries too large", redlog::field("count", record.entries.size()));
    return false;
  }
  writer.write_u32(static_cast<uint32_t>(record.entries.size()));
  for (const auto& entry : record.entries) {
    if (!encode_reg_write_entry(entry, writer, log)) {
      return false;
    }
  }
  return true;
}

inline bool decode_reg_write(trace_buffer_reader& reader, reg_write_record& out) {
  uint32_t count = 0;
  if (!reader.read_u64(out.thread_id) || !reader.read_u64(out.sequence) || !reader.read_u32(out.regfile_id) ||
      !reader.read_u32(count)) {
    return false;
  }
  out.entries.clear();
  out.entries.reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    reg_write_entry entry{};
    if (!decode_reg_write_entry(reader, entry)) {
      return false;
    }
    out.entries.push_back(std::move(entry));
  }
  return true;
}

inline bool encode_mem_access(const mem_access_record& record, trace_buffer_writer& writer, redlog::logger& log) {
  writer.write_u64(record.thread_id);
  writer.write_u64(record.sequence);
  writer.write_u32(record.space_id);
  writer.write_u8(static_cast<uint8_t>(record.op));
  writer.write_u8(record.flags);
  writer.write_u16(0);
  writer.write_u64(record.address);
  writer.write_u32(record.access_size);
  if (record.value.size() > std::numeric_limits<uint32_t>::max()) {
    log.err("memory access value too large", redlog::field("size", record.value.size()));
    return false;
  }
  writer.write_u32(static_cast<uint32_t>(record.value.size()));
  if (!record.value.empty()) {
    writer.write_bytes(record.value.data(), record.value.size());
  }
  return true;
}

inline bool decode_mem_access(trace_buffer_reader& reader, mem_access_record& out) {
  uint8_t op = 0;
  uint32_t value_size = 0;
  if (!reader.read_u64(out.thread_id) || !reader.read_u64(out.sequence) || !reader.read_u32(out.space_id) ||
      !reader.read_u8(op) || !reader.read_u8(out.flags)) {
    return false;
  }
  uint16_t reserved = 0;
  if (!reader.read_u16(reserved) || !reader.read_u64(out.address) || !reader.read_u32(out.access_size) ||
      !reader.read_u32(value_size)) {
    return false;
  }
  (void) reserved;
  out.op = static_cast<mem_access_op>(op);
  if (value_size > 0) {
    if (!reader.read_bytes(out.value, value_size)) {
      return false;
    }
  } else {
    out.value.clear();
  }
  return true;
}

inline bool encode_snapshot(const snapshot_record& record, trace_buffer_writer& writer, redlog::logger& log) {
  writer.write_u64(record.thread_id);
  writer.write_u64(record.sequence);
  writer.write_u32(record.regfile_id);
  if (record.registers.size() > std::numeric_limits<uint32_t>::max()) {
    log.err("snapshot register list too large", redlog::field("count", record.registers.size()));
    return false;
  }
  writer.write_u32(static_cast<uint32_t>(record.registers.size()));
  for (const auto& entry : record.registers) {
    if (!encode_reg_write_entry(entry, writer, log)) {
      return false;
    }
  }
  if (record.memory_segments.size() > std::numeric_limits<uint32_t>::max()) {
    log.err("snapshot memory segments too large", redlog::field("count", record.memory_segments.size()));
    return false;
  }
  writer.write_u32(static_cast<uint32_t>(record.memory_segments.size()));
  for (const auto& segment : record.memory_segments) {
    writer.write_u32(segment.space_id);
    writer.write_u64(segment.base);
    if (segment.bytes.size() > std::numeric_limits<uint32_t>::max()) {
      log.err("snapshot memory segment too large", redlog::field("size", segment.bytes.size()));
      return false;
    }
    writer.write_u32(static_cast<uint32_t>(segment.bytes.size()));
    if (!segment.bytes.empty()) {
      writer.write_bytes(segment.bytes.data(), segment.bytes.size());
    }
  }
  return true;
}

inline bool decode_snapshot(trace_buffer_reader& reader, snapshot_record& out) {
  uint32_t reg_count = 0;
  if (!reader.read_u64(out.thread_id) || !reader.read_u64(out.sequence) || !reader.read_u32(out.regfile_id) ||
      !reader.read_u32(reg_count)) {
    return false;
  }
  out.registers.clear();
  out.registers.reserve(reg_count);
  for (uint32_t i = 0; i < reg_count; ++i) {
    reg_write_entry entry{};
    if (!decode_reg_write_entry(reader, entry)) {
      return false;
    }
    out.registers.push_back(std::move(entry));
  }
  uint32_t seg_count = 0;
  if (!reader.read_u32(seg_count)) {
    return false;
  }
  out.memory_segments.clear();
  out.memory_segments.reserve(seg_count);
  for (uint32_t i = 0; i < seg_count; ++i) {
    memory_segment segment{};
    uint32_t size = 0;
    if (!reader.read_u32(segment.space_id) || !reader.read_u64(segment.base) || !reader.read_u32(size)) {
      return false;
    }
    if (size > 0) {
      if (!reader.read_bytes(segment.bytes, size)) {
        return false;
      }
    }
    out.memory_segments.push_back(std::move(segment));
  }
  return true;
}

inline bool encode_meta(const meta_record& record, trace_buffer_writer& writer, redlog::logger& log) {
  writer.write_u8(static_cast<uint8_t>(record.scope_kind));
  writer.write_u8(0);
  writer.write_u16(0);
  writer.write_u64(record.scope_id);
  if (!write_string_checked(writer, record.key, log) || !write_string_checked(writer, record.value, log)) {
    return false;
  }
  return true;
}

inline bool decode_meta(trace_buffer_reader& reader, meta_record& out) {
  uint8_t scope = 0;
  uint8_t reserved8 = 0;
  uint16_t reserved16 = 0;
  if (!reader.read_u8(scope) || !reader.read_u8(reserved8) || !reader.read_u16(reserved16) ||
      !reader.read_u64(out.scope_id) || !reader.read_string(out.key) || !reader.read_string(out.value)) {
    return false;
  }
  (void) reserved8;
  (void) reserved16;
  out.scope_kind = static_cast<meta_scope_kind>(scope);
  return true;
}

} // namespace w1::rewind
