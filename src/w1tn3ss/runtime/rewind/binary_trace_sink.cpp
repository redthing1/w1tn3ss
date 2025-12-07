#include "binary_trace_sink.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <limits>
#include <sstream>
#include <system_error>

#if defined(_WIN32)
#include <process.h>
#else
#include <unistd.h>
#endif

#include <QBDI/Config.h>

namespace w1::rewind {
namespace {

constexpr char k_magic[] = {'W', '1', 'R', 'W', 'N', 'D', '\n', '\0'};

} // namespace

binary_trace_sink::binary_trace_sink(binary_trace_sink_config config) : config_(std::move(config)) {}

binary_trace_sink::~binary_trace_sink() { close(); }

std::shared_ptr<binary_trace_sink> make_binary_trace_sink(binary_trace_sink_config config) {
  return std::make_shared<binary_trace_sink>(std::move(config));
}

bool binary_trace_sink::initialize() {
  std::lock_guard<std::mutex> guard(mutex_);
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

  if (!good_) {
    config_.log.err("failed to open trace", redlog::field("path", path_));
    return false;
  }

  write_header();
  if (!good_) {
    config_.log.err("failed to write trace header", redlog::field("path", path_));
  } else {
    config_.log.inf("trace writer ready", redlog::field("path", path_));
  }

  return good_;
}

void binary_trace_sink::close() {
  std::lock_guard<std::mutex> guard(mutex_);
  if (stream_.is_open()) {
    stream_.flush();
    stream_.close();
  }

  if (good_) {
    config_.log.dbg("trace writer closed", redlog::field("path", path_));
  }

  good_ = false;
  header_written_ = false;
}

bool binary_trace_sink::write_event(const trace_event& event) {
  std::lock_guard<std::mutex> guard(mutex_);
  if (!good_) {
    return false;
  }

  if (!header_written_) {
    write_header();
    if (!good_) {
      return false;
    }
  }

  const event_type type = (event.type == trace_event_type::boundary) ? event_type::boundary : event_type::instruction;
  write_u8(static_cast<uint8_t>(type));
  write_u64(event.thread_id);
  write_u64(event.sequence);
  write_u64(event.address);
  write_u32(event.size);

  write_u32(static_cast<uint32_t>(event.registers.size()));
  for (const auto& reg : event.registers) {
    write_string(reg.name);
    write_u64(reg.value);
  }

  write_memory_list(event.reads);
  write_memory_list(event.writes);

  if (event.boundary.has_value()) {
    write_u8(1);
    write_u64(event.boundary->boundary_id);
    write_u32(event.boundary->flags);
    write_string(event.boundary->reason);
  } else {
    write_u8(0);
  }

  if (!stream_.good()) {
    mark_failure();
  }

  if (good_) {
    notify_observers(event);
  }

  return good_;
}

void binary_trace_sink::flush() {
  std::lock_guard<std::mutex> guard(mutex_);
  if (stream_.is_open()) {
    stream_.flush();
  }
}

std::string binary_trace_sink::make_default_path() const {
  std::filesystem::path base;
  std::error_code ec;
  base = std::filesystem::current_path(ec);
  if (ec) {
    base.clear();
  }

#if defined(_WIN32)
  int pid = _getpid();
#else
  int pid = static_cast<int>(getpid());
#endif

  std::ostringstream name;
  name << "w1rewind_" << pid << ".trace";

  if (!base.empty()) {
    base /= name.str();
    return base.string();
  }

  return name.str();
}

void binary_trace_sink::write_header() {
  if (header_written_) {
    return;
  }

  file_header header{};
  std::copy(std::begin(k_magic), std::end(k_magic), header.magic);
  header.version = 3;
  header.flags = 0;
  header.architecture = detect_architecture();

  write_bytes(&header, sizeof(header));

  if (good_) {
    header_written_ = true;
  }
}

void binary_trace_sink::write_u8(uint8_t value) {
  stream_.put(static_cast<char>(value));
  if (!stream_.good()) {
    mark_failure();
  }
}

void binary_trace_sink::write_u16(uint16_t value) {
  std::array<uint8_t, 2> buffer{};
  buffer[0] = static_cast<uint8_t>(value & 0xFF);
  buffer[1] = static_cast<uint8_t>((value >> 8) & 0xFF);
  write_bytes(buffer.data(), buffer.size());
}

void binary_trace_sink::write_u32(uint32_t value) {
  std::array<uint8_t, 4> buffer{};
  for (size_t i = 0; i < buffer.size(); ++i) {
    buffer[i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
  }
  write_bytes(buffer.data(), buffer.size());
}

void binary_trace_sink::write_u64(uint64_t value) {
  std::array<uint8_t, 8> buffer{};
  for (size_t i = 0; i < buffer.size(); ++i) {
    buffer[i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
  }
  write_bytes(buffer.data(), buffer.size());
}

void binary_trace_sink::write_bytes(const void* data, size_t size) {
  if (!good_ || size == 0) {
    return;
  }

  stream_.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
  if (!stream_.good()) {
    mark_failure();
  }
}

void binary_trace_sink::write_string(const std::string& value) {
  if (value.size() > std::numeric_limits<uint16_t>::max()) {
    config_.log.err("trace string too long", redlog::field("length", value.size()));
    mark_failure();
    return;
  }

  write_u16(static_cast<uint16_t>(value.size()));
  if (!value.empty()) {
    write_bytes(value.data(), value.size());
  }
}

void binary_trace_sink::write_memory_list(const std::vector<trace_memory_delta>& accesses) {
  write_u32(static_cast<uint32_t>(accesses.size()));
  for (const auto& mem : accesses) {
    write_u64(mem.address);
    write_u32(mem.size);
    write_u8(mem.value_known ? 1 : 0);
    write_u32(static_cast<uint32_t>(mem.data.size()));
    if (!mem.data.empty()) {
      write_bytes(mem.data.data(), mem.data.size());
    }
  }
}

void binary_trace_sink::mark_failure() {
  if (!good_) {
    return;
  }

  good_ = false;
  config_.log.err("trace writer failure", redlog::field("path", path_));
}

uint32_t binary_trace_sink::detect_architecture() const {
#if defined(QBDI_ARCH_X86_64)
  return 0x0101;
#elif defined(QBDI_ARCH_X86)
  return 0x0102;
#elif defined(QBDI_ARCH_AARCH64)
  return 0x0201;
#elif defined(QBDI_ARCH_ARM)
  return 0x0202;
#else
  return 0;
#endif
}

} // namespace w1::rewind
