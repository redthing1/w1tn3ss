#include "trace_writer.hpp"

#include <array>
#include <filesystem>
#include <limits>
#include <sstream>
#include <system_error>

#if defined(W1_REWIND_HAVE_ZSTD)
#include <zstd.h>
#endif

#if defined(_WIN32)
#include <process.h>
#else
#include <unistd.h>
#endif

namespace w1::rewind {

namespace {

constexpr int k_zstd_level = 3;

} // namespace

trace_writer::trace_writer(trace_writer_config config) : config_(std::move(config)) {}

trace_writer::~trace_writer() { close(); }

std::shared_ptr<trace_writer> make_trace_writer(trace_writer_config config) {
  return std::make_shared<trace_writer>(std::move(config));
}

bool trace_writer::open() {
  std::lock_guard<std::mutex> guard(mutex_);
#if !defined(W1_REWIND_HAVE_ZSTD)
  if (config_.compression == trace_compression::zstd) {
    config_.log.err("zstd compression requested but zstd is not available");
    good_ = false;
    return false;
  }
#endif

  if (config_.chunk_size == 0) {
    config_.chunk_size = k_trace_chunk_bytes;
  }
  if (stream_.is_open()) {
    stream_.close();
  }

  path_ = config_.path;
  if (path_.empty()) {
    path_ = make_default_path();
  }

  std::error_code ec;
  std::filesystem::path fs_path(path_);
  if (fs_path.has_parent_path()) {
    std::filesystem::create_directories(fs_path.parent_path(), ec);
    if (ec) {
      config_.log.err(
          "failed to create trace directory", redlog::field("path", fs_path.parent_path().string()),
          redlog::field("error", ec.message())
      );
      good_ = false;
      return false;
    }
  }

  stream_.open(fs_path, std::ios::binary | std::ios::out | std::ios::trunc);
  good_ = stream_.good();
  header_written_ = false;
  chunk_buffer_.clear();
  chunk_encoded_.clear();

  if (!good_) {
    config_.log.err("failed to open trace", redlog::field("path", path_));
    return false;
  }

  config_.log.inf("trace writer ready", redlog::field("path", path_));
  return true;
}

void trace_writer::close() {
  std::lock_guard<std::mutex> guard(mutex_);
  if (stream_.is_open()) {
    if (good_ && header_written_) {
      flush_chunk_locked();
      stream_.flush();
    }
    stream_.close();
  }
  good_ = false;
  header_written_ = false;
  chunk_buffer_.clear();
  chunk_encoded_.clear();
}

bool trace_writer::write_header(const trace_header& header) {
  std::lock_guard<std::mutex> guard(mutex_);
  if (!stream_.is_open()) {
    config_.log.err("trace writer not open");
    return false;
  }
  if (header_written_) {
    return true;
  }

  trace_header updated = header;
  updated.compression = config_.compression;
  updated.chunk_size = config_.chunk_size;

  write_bytes(k_trace_magic.data(), k_trace_magic.size());
  write_u16(updated.version);
  write_u16(static_cast<uint16_t>(updated.architecture));
  write_u32(updated.pointer_size);
  write_u64(updated.flags);
  write_u32(static_cast<uint32_t>(updated.compression));
  write_u32(updated.chunk_size);

  if (good_) {
    header_written_ = true;
  } else {
    config_.log.err("failed to write trace header", redlog::field("path", path_));
  }

  return good_;
}

bool trace_writer::write_register_table(const register_table_record& record) {
  std::vector<uint8_t> payload;
  if (record.names.size() > std::numeric_limits<uint16_t>::max()) {
    config_.log.err("register table too large", redlog::field("count", record.names.size()));
    return false;
  }

  append_u16(payload, static_cast<uint16_t>(record.names.size()));
  for (const auto& name : record.names) {
    if (!append_string(payload, name, config_.log)) {
      return false;
    }
  }

  return write_record(record_kind::register_table, 0, payload);
}

bool trace_writer::write_module_table(const module_table_record& record) {
  std::vector<uint8_t> payload;
  if (record.modules.size() > std::numeric_limits<uint32_t>::max()) {
    config_.log.err("module table too large", redlog::field("count", record.modules.size()));
    return false;
  }

  append_u32(payload, static_cast<uint32_t>(record.modules.size()));
  for (const auto& module : record.modules) {
    append_u64(payload, module.id);
    append_u64(payload, module.base);
    append_u64(payload, module.size);
    append_u32(payload, module.permissions);
    if (!append_string(payload, module.path, config_.log)) {
      return false;
    }
  }

  return write_record(record_kind::module_table, 0, payload);
}

bool trace_writer::write_thread_start(const thread_start_record& record) {
  std::vector<uint8_t> payload;
  append_u64(payload, record.thread_id);
  if (!append_string(payload, record.name, config_.log)) {
    return false;
  }
  return write_record(record_kind::thread_start, 0, payload);
}

bool trace_writer::write_instruction(const instruction_record& record) {
  std::vector<uint8_t> payload;
  append_u64(payload, record.sequence);
  append_u64(payload, record.thread_id);
  append_u64(payload, record.module_id);
  append_u64(payload, record.module_offset);
  append_u32(payload, record.size);
  append_u32(payload, record.flags);
  return write_record(record_kind::instruction, 0, payload);
}

bool trace_writer::write_block_definition(const block_definition_record& record) {
  std::vector<uint8_t> payload;
  append_u64(payload, record.block_id);
  append_u64(payload, record.module_id);
  append_u64(payload, record.module_offset);
  append_u32(payload, record.size);
  return write_record(record_kind::block_definition, 0, payload);
}

bool trace_writer::write_block_exec(const block_exec_record& record) {
  std::vector<uint8_t> payload;
  append_u64(payload, record.sequence);
  append_u64(payload, record.thread_id);
  append_u64(payload, record.block_id);
  return write_record(record_kind::block_exec, 0, payload);
}

bool trace_writer::write_register_deltas(const register_delta_record& record) {
  std::vector<uint8_t> payload;
  if (record.deltas.size() > std::numeric_limits<uint16_t>::max()) {
    config_.log.err("register delta list too large", redlog::field("count", record.deltas.size()));
    return false;
  }

  append_u64(payload, record.sequence);
  append_u64(payload, record.thread_id);
  append_u16(payload, static_cast<uint16_t>(record.deltas.size()));
  for (const auto& delta : record.deltas) {
    append_u16(payload, delta.reg_id);
    append_u64(payload, delta.value);
  }
  return write_record(record_kind::register_deltas, 0, payload);
}

bool trace_writer::write_memory_access(const memory_access_record& record) {
  std::vector<uint8_t> payload;
  if (record.data.size() > std::numeric_limits<uint32_t>::max()) {
    config_.log.err("memory record data too large", redlog::field("size", record.data.size()));
    return false;
  }

  append_u64(payload, record.sequence);
  append_u64(payload, record.thread_id);
  append_u8(payload, static_cast<uint8_t>(record.kind));
  append_u8(payload, record.value_known ? 1 : 0);
  append_u8(payload, record.value_truncated ? 1 : 0);
  append_u8(payload, 0);
  append_u64(payload, record.address);
  append_u32(payload, record.size);
  append_u32(payload, static_cast<uint32_t>(record.data.size()));
  if (!record.data.empty()) {
    payload.insert(payload.end(), record.data.begin(), record.data.end());
  }

  return write_record(record_kind::memory_access, 0, payload);
}

bool trace_writer::write_boundary(const boundary_record& record) {
  std::vector<uint8_t> payload;
  if (record.registers.size() > std::numeric_limits<uint16_t>::max()) {
    config_.log.err("boundary register list too large", redlog::field("count", record.registers.size()));
    return false;
  }
  if (record.stack_window.size() > std::numeric_limits<uint32_t>::max()) {
    config_.log.err("boundary stack window too large", redlog::field("size", record.stack_window.size()));
    return false;
  }

  append_u64(payload, record.boundary_id);
  append_u64(payload, record.sequence);
  append_u64(payload, record.thread_id);
  append_u16(payload, static_cast<uint16_t>(record.registers.size()));
  for (const auto& reg : record.registers) {
    append_u16(payload, reg.reg_id);
    append_u64(payload, reg.value);
  }
  append_u32(payload, static_cast<uint32_t>(record.stack_window.size()));
  if (!record.stack_window.empty()) {
    payload.insert(payload.end(), record.stack_window.begin(), record.stack_window.end());
  }
  if (!append_string(payload, record.reason, config_.log)) {
    return false;
  }

  return write_record(record_kind::boundary, 0, payload);
}

bool trace_writer::write_thread_end(const thread_end_record& record) {
  std::vector<uint8_t> payload;
  append_u64(payload, record.thread_id);
  return write_record(record_kind::thread_end, 0, payload);
}

void trace_writer::flush() {
  std::lock_guard<std::mutex> guard(mutex_);
  if (!good_) {
    return;
  }
  flush_chunk_locked();
  stream_.flush();
  if (!stream_.good()) {
    mark_failure();
  }
}

bool trace_writer::write_record(record_kind kind, uint16_t flags, const std::vector<uint8_t>& payload) {
  std::lock_guard<std::mutex> guard(mutex_);
  if (!good_) {
    return false;
  }
  if (!header_written_) {
    config_.log.err("trace header not written", redlog::field("path", path_));
    mark_failure();
    return false;
  }

  append_u16(chunk_buffer_, static_cast<uint16_t>(kind));
  append_u16(chunk_buffer_, flags);
  append_u32(chunk_buffer_, static_cast<uint32_t>(payload.size()));
  if (!payload.empty()) {
    chunk_buffer_.insert(chunk_buffer_.end(), payload.begin(), payload.end());
  }

  if (chunk_buffer_.size() >= config_.chunk_size) {
    return flush_chunk_locked();
  }

  return good_;
}

bool trace_writer::flush_chunk_locked() {
  if (!good_) {
    return false;
  }
  if (chunk_buffer_.empty()) {
    return true;
  }
  if (chunk_buffer_.size() > std::numeric_limits<uint32_t>::max()) {
    config_.log.err("trace chunk too large", redlog::field("size", chunk_buffer_.size()));
    mark_failure();
    return false;
  }

  uint32_t uncompressed_size = static_cast<uint32_t>(chunk_buffer_.size());
  if (config_.compression == trace_compression::none) {
    write_u32(uncompressed_size);
    write_u32(uncompressed_size);
    write_bytes(chunk_buffer_.data(), chunk_buffer_.size());
    chunk_buffer_.clear();
    return good_;
  }

  if (config_.compression != trace_compression::zstd) {
    config_.log.err("unsupported trace compression mode");
    mark_failure();
    return false;
  }

#if defined(W1_REWIND_HAVE_ZSTD)
  size_t bound = ZSTD_compressBound(chunk_buffer_.size());
  if (bound > std::numeric_limits<uint32_t>::max()) {
    config_.log.err("compressed chunk bound too large", redlog::field("size", bound));
    mark_failure();
    return false;
  }
  chunk_encoded_.resize(bound);
  size_t compressed_size = ZSTD_compress(
      chunk_encoded_.data(), bound, chunk_buffer_.data(), chunk_buffer_.size(), k_zstd_level
  );
  if (ZSTD_isError(compressed_size)) {
    config_.log.err("zstd compression failed", redlog::field("error", ZSTD_getErrorName(compressed_size)));
    mark_failure();
    return false;
  }
  if (compressed_size > std::numeric_limits<uint32_t>::max()) {
    config_.log.err("compressed chunk too large", redlog::field("size", compressed_size));
    mark_failure();
    return false;
  }
  write_u32(static_cast<uint32_t>(compressed_size));
  write_u32(uncompressed_size);
  write_bytes(chunk_encoded_.data(), compressed_size);
  chunk_buffer_.clear();
  return good_;
#else
  config_.log.err("zstd compression requested but zstd is not available");
  mark_failure();
  return false;
#endif
}

void trace_writer::write_u8(uint8_t value) {
  stream_.put(static_cast<char>(value));
  if (!stream_.good()) {
    mark_failure();
  }
}

void trace_writer::write_u16(uint16_t value) {
  std::array<uint8_t, 2> buffer{};
  buffer[0] = static_cast<uint8_t>(value & 0xFF);
  buffer[1] = static_cast<uint8_t>((value >> 8) & 0xFF);
  write_bytes(buffer.data(), buffer.size());
}

void trace_writer::write_u32(uint32_t value) {
  std::array<uint8_t, 4> buffer{};
  for (size_t i = 0; i < buffer.size(); ++i) {
    buffer[i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
  }
  write_bytes(buffer.data(), buffer.size());
}

void trace_writer::write_u64(uint64_t value) {
  std::array<uint8_t, 8> buffer{};
  for (size_t i = 0; i < buffer.size(); ++i) {
    buffer[i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
  }
  write_bytes(buffer.data(), buffer.size());
}

void trace_writer::write_bytes(const void* data, size_t size) {
  if (!good_ || size == 0) {
    return;
  }
  stream_.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
  if (!stream_.good()) {
    mark_failure();
  }
}

void trace_writer::mark_failure() {
  good_ = false;
}

std::string trace_writer::make_default_path() const {
  std::filesystem::path base = std::filesystem::current_path();
#if defined(_WIN32)
  int pid = static_cast<int>(_getpid());
#else
  int pid = static_cast<int>(getpid());
#endif

  std::ostringstream name;
  name << "w1rewind_" << pid << ".trace";
  base /= name.str();
  return base.string();
}

void trace_writer::append_u8(std::vector<uint8_t>& out, uint8_t value) {
  out.push_back(value);
}

void trace_writer::append_u16(std::vector<uint8_t>& out, uint16_t value) {
  out.push_back(static_cast<uint8_t>(value & 0xFF));
  out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
}

void trace_writer::append_u32(std::vector<uint8_t>& out, uint32_t value) {
  for (size_t i = 0; i < 4; ++i) {
    out.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
  }
}

void trace_writer::append_u64(std::vector<uint8_t>& out, uint64_t value) {
  for (size_t i = 0; i < 8; ++i) {
    out.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
  }
}

bool trace_writer::append_string(std::vector<uint8_t>& out, const std::string& value, redlog::logger& log) {
  if (value.size() > std::numeric_limits<uint16_t>::max()) {
    log.err("trace string too long", redlog::field("length", value.size()));
    return false;
  }
  append_u16(out, static_cast<uint16_t>(value.size()));
  out.insert(out.end(), value.begin(), value.end());
  return true;
}

} // namespace w1::rewind
