#include "trace_builder.hpp"

#include "w1rewind/format/trace_codec.hpp"

namespace w1::rewind {

trace_builder::trace_builder(trace_builder_config config) : config_(std::move(config)) {}

bool trace_builder::begin_trace(const file_header& header) {
  if (started_) {
    error_ = "trace already started";
    return false;
  }
  if (!config_.sink) {
    error_ = "trace sink missing";
    return false;
  }
  if (!config_.sink->good()) {
    error_ = "trace sink not ready";
    return false;
  }
  if (!config_.sink->write_header(header)) {
    error_ = "failed to write trace header";
    return false;
  }
  started_ = true;
  return true;
}

bool trace_builder::write_record(const record_header& header, std::span<const uint8_t> payload) {
  if (!ensure_trace_started()) {
    return false;
  }
  if (!config_.sink->write_record(header, payload)) {
    error_ = "failed to write record";
    return false;
  }
  return true;
}

bool trace_builder::emit_with_codec(uint32_t type_id, const std::vector<uint8_t>& payload) {
  record_header header{};
  header.type_id = type_id;
  header.version = 1;
  header.flags = 0;
  header.payload_size = static_cast<uint32_t>(payload.size());
  return write_record(header, payload);
}

bool trace_builder::emit_record_type_dictionary(const record_type_dictionary_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  if (!encode_record_type_dictionary(record, writer, config_.log)) {
    error_ = "failed to encode record type dictionary";
    return false;
  }
  return emit_with_codec(k_record_type_dictionary, payload);
}

bool trace_builder::emit_arch_descriptor(const arch_descriptor_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  if (!encode_arch_descriptor(record, writer, config_.log)) {
    error_ = "failed to encode arch descriptor";
    return false;
  }
  return emit_with_codec(k_record_type_arch_descriptor, payload);
}

bool trace_builder::emit_arch_descriptor_checked(const arch_descriptor_record& record) {
  if (record.arch_id.empty()) {
    error_ = "arch descriptor missing arch_id";
    return false;
  }
  if (record.pointer_bits == 0 && record.address_bits == 0) {
    error_ = "arch descriptor missing pointer/address size";
    return false;
  }
  return emit_arch_descriptor(record);
}

bool trace_builder::emit_environment(const environment_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  if (!encode_environment(record, writer, config_.log)) {
    error_ = "failed to encode environment";
    return false;
  }
  return emit_with_codec(k_record_type_environment, payload);
}

bool trace_builder::emit_environment_checked(const environment_record& record) {
  if (record.os_id.empty()) {
    error_ = "environment missing os_id";
    return false;
  }
  return emit_environment(record);
}

bool trace_builder::emit_address_space(const address_space_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  if (!encode_address_space(record, writer, config_.log)) {
    error_ = "failed to encode address space";
    return false;
  }
  return emit_with_codec(k_record_type_address_space, payload);
}

bool trace_builder::emit_register_file(const register_file_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  if (!encode_register_file(record, writer, config_.log)) {
    error_ = "failed to encode register file";
    return false;
  }
  return emit_with_codec(k_record_type_register_file, payload);
}

bool trace_builder::emit_image(const image_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  if (!encode_image(record, writer, config_.log)) {
    error_ = "failed to encode image";
    return false;
  }
  return emit_with_codec(k_record_type_image, payload);
}

bool trace_builder::emit_image_metadata(const image_metadata_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  if (!encode_image_metadata(record, writer, config_.log)) {
    error_ = "failed to encode image metadata";
    return false;
  }
  return emit_with_codec(k_record_type_image_metadata, payload);
}

bool trace_builder::emit_image_blob(const image_blob_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  if (!encode_image_blob(record, writer, config_.log)) {
    error_ = "failed to encode image blob";
    return false;
  }
  return emit_with_codec(k_record_type_image_blob, payload);
}

bool trace_builder::emit_image_blob_range(uint64_t image_id, uint64_t offset, std::span<const uint8_t> bytes) {
  if (bytes.empty()) {
    return true;
  }
  image_blob_record record{};
  record.image_id = image_id;
  record.offset = offset;
  record.data.assign(bytes.begin(), bytes.end());
  return emit_image_blob(record);
}

bool trace_builder::emit_mapping(const mapping_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  if (!encode_mapping(record, writer, config_.log)) {
    error_ = "failed to encode mapping";
    return false;
  }
  return emit_with_codec(k_record_type_mapping, payload);
}

bool trace_builder::emit_thread_start(const thread_start_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  if (!encode_thread_start(record, writer, config_.log)) {
    error_ = "failed to encode thread start";
    return false;
  }
  return emit_with_codec(k_record_type_thread_start, payload);
}

bool trace_builder::emit_thread_end(const thread_end_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  if (!encode_thread_end(record, writer)) {
    error_ = "failed to encode thread end";
    return false;
  }
  return emit_with_codec(k_record_type_thread_end, payload);
}

bool trace_builder::emit_flow_instruction(const flow_instruction_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  encode_flow_instruction(record, writer);
  return emit_with_codec(k_record_type_flow_instruction, payload);
}

bool trace_builder::emit_block_definition(const block_definition_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  encode_block_definition(record, writer);
  return emit_with_codec(k_record_type_block_definition, payload);
}

bool trace_builder::emit_block_exec(const block_exec_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  encode_block_exec(record, writer);
  return emit_with_codec(k_record_type_block_exec, payload);
}

bool trace_builder::emit_reg_write(const reg_write_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  if (!encode_reg_write(record, writer, config_.log)) {
    error_ = "failed to encode reg write";
    return false;
  }
  return emit_with_codec(k_record_type_reg_write, payload);
}

bool trace_builder::emit_mem_access(const mem_access_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  if (!encode_mem_access(record, writer, config_.log)) {
    error_ = "failed to encode mem access";
    return false;
  }
  return emit_with_codec(k_record_type_mem_access, payload);
}

bool trace_builder::emit_snapshot(const snapshot_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  if (!encode_snapshot(record, writer, config_.log)) {
    error_ = "failed to encode snapshot";
    return false;
  }
  return emit_with_codec(k_record_type_snapshot, payload);
}

bool trace_builder::emit_meta(const meta_record& record) {
  std::vector<uint8_t> payload;
  trace_buffer_writer writer(payload);
  if (!encode_meta(record, writer, config_.log)) {
    error_ = "failed to encode meta";
    return false;
  }
  return emit_with_codec(k_record_type_meta, payload);
}

bool trace_builder::begin_thread(uint64_t thread_id, std::string name) {
  if (!ensure_trace_started()) {
    return false;
  }
  auto& state = threads_[thread_id];
  if (!name.empty() && state.name.empty()) {
    state.name = std::move(name);
  }
  return ensure_thread_started(state, thread_id);
}

bool trace_builder::end_thread(uint64_t thread_id) {
  if (!ensure_trace_started()) {
    return false;
  }
  auto& state = threads_[thread_id];
  if (!ensure_thread_started(state, thread_id)) {
    return false;
  }
  if (state.ended) {
    return true;
  }
  thread_end_record end{};
  end.thread_id = thread_id;
  if (!emit_thread_end(end)) {
    return false;
  }
  state.ended = true;
  return true;
}

bool trace_builder::emit_instruction(
    uint64_t thread_id, uint64_t address, uint32_t size, uint32_t space_id, uint16_t mode_id, uint64_t& sequence_out
) {
  if (!ensure_trace_started()) {
    return false;
  }
  auto& state = threads_[thread_id];
  if (!ensure_thread_started(state, thread_id)) {
    return false;
  }

  flow_instruction_record record{};
  record.thread_id = thread_id;
  record.sequence = state.next_sequence++;
  record.space_id = space_id;
  record.mode_id = mode_id;
  record.address = address;
  record.size = size;

  if (!emit_flow_instruction(record)) {
    return false;
  }

  sequence_out = record.sequence;
  return true;
}

bool trace_builder::emit_block(
    uint64_t thread_id, uint64_t address, uint32_t size, uint32_t space_id, uint16_t mode_id, uint64_t& sequence_out
) {
  if (!ensure_trace_started()) {
    return false;
  }
  auto& state = threads_[thread_id];
  if (!ensure_thread_started(state, thread_id)) {
    return false;
  }

  block_key key{};
  key.address = address;
  key.size = size;
  key.space_id = space_id;
  key.mode_id = mode_id;

  uint64_t block_id = 0;
  auto it = block_ids_.find(key);
  if (it == block_ids_.end()) {
    block_id = next_block_id_++;
    block_ids_[key] = block_id;
    block_definition_record def{};
    def.block_id = block_id;
    def.space_id = space_id;
    def.mode_id = mode_id;
    def.address = address;
    def.size = size;
    if (!emit_block_definition(def)) {
      return false;
    }
  } else {
    block_id = it->second;
  }

  block_exec_record exec{};
  exec.thread_id = thread_id;
  exec.sequence = state.next_sequence++;
  exec.block_id = block_id;

  if (!emit_block_exec(exec)) {
    return false;
  }

  sequence_out = exec.sequence;
  return true;
}

void trace_builder::flush() {
  if (config_.sink) {
    config_.sink->flush();
  }
}

bool trace_builder::good() const {
  if (!config_.sink) {
    return false;
  }
  return config_.sink->good();
}

bool trace_builder::ensure_trace_started() {
  if (started_) {
    return true;
  }
  error_ = "trace not started";
  return false;
}

bool trace_builder::ensure_thread_started(thread_state& state, uint64_t thread_id) {
  if (state.started) {
    return true;
  }

  thread_start_record start{};
  start.thread_id = thread_id;
  start.name = state.name;
  if (!emit_thread_start(start)) {
    return false;
  }
  state.started = true;
  return true;
}

} // namespace w1::rewind
