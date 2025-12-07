#include "binary_trace_source.hpp"

#include <array>
#include <limits>

namespace w1::rewind {
namespace {

constexpr char k_magic[] = {'W', '1', 'R', 'W', 'N', 'D', '\n', '\0'};

struct file_header {
  char magic[8];
  uint32_t version = 0;
  uint32_t flags = 0;
  uint32_t architecture = 0;
  uint32_t reserved = 0;
};

} // namespace

binary_trace_source::binary_trace_source(binary_trace_source_config config) : config_(std::move(config)) {}

binary_trace_source::~binary_trace_source() { close(); }

std::shared_ptr<binary_trace_source> make_binary_trace_source(binary_trace_source_config config) {
  return std::make_shared<binary_trace_source>(std::move(config));
}

bool binary_trace_source::initialize() {
  close();

  if (config_.path.empty()) {
    config_.log.err("trace source requires a path");
    return false;
  }

  stream_.open(config_.path, std::ios::binary | std::ios::in);
  if (!stream_.good()) {
    config_.log.err("failed to open trace", redlog::field("path", config_.path));
    return false;
  }

  if (!read_header()) {
    config_.log.err("invalid trace header", redlog::field("path", config_.path));
    close();
    return false;
  }

  config_.log.inf("trace source ready", redlog::field("path", config_.path), redlog::field("version", version_));
  return true;
}

void binary_trace_source::close() {
  if (stream_.is_open()) {
    stream_.close();
  }
  version_ = 0;
}

void binary_trace_source::reset() {
  if (!stream_.is_open()) {
    return;
  }
  stream_.clear();
  stream_.seekg(0, std::ios::beg);
  read_header();
}

bool binary_trace_source::read_header() {
  file_header header{};
  stream_.read(reinterpret_cast<char*>(&header), sizeof(header));
  if (!stream_.good()) {
    return false;
  }

  if (!std::equal(std::begin(k_magic), std::end(k_magic), header.magic)) {
    return false;
  }

  if (header.version < 1 || header.version > 3) {
    return false;
  }

  version_ = header.version;
  return true;
}

bool binary_trace_source::read_event(trace_event& event) {
  if (!stream_.good()) {
    return false;
  }

  uint8_t event_type = 0;
  stream_.read(reinterpret_cast<char*>(&event_type), sizeof(event_type));
  if (!stream_.good()) {
    return false;
  }

  switch (event_type) {
  case 1:
    event.type = trace_event_type::instruction;
    break;
  case 2:
    event.type = trace_event_type::boundary;
    break;
  default:
    config_.log.err("unsupported event type in trace", redlog::field("type", event_type));
    return false;
  }

  stream_.read(reinterpret_cast<char*>(&event.thread_id), sizeof(event.thread_id));
  stream_.read(reinterpret_cast<char*>(&event.sequence), sizeof(event.sequence));
  stream_.read(reinterpret_cast<char*>(&event.address), sizeof(event.address));
  stream_.read(reinterpret_cast<char*>(&event.size), sizeof(event.size));
  if (!stream_.good()) {
    return false;
  }

  if (!read_registers(event)) {
    return false;
  }

  if (version_ >= 2) {
    if (!read_memory_list(event.reads)) {
      return false;
    }
  } else {
    event.reads.clear();
  }

  if (!read_memory_list(event.writes)) {
    return false;
  }

  if (version_ >= 3) {
    uint8_t has_boundary = 0;
    stream_.read(reinterpret_cast<char*>(&has_boundary), sizeof(has_boundary));
    if (!stream_.good()) {
      return false;
    }
    if (has_boundary != 0) {
      trace_event::trace_boundary_info info{};
      stream_.read(reinterpret_cast<char*>(&info.boundary_id), sizeof(info.boundary_id));
      stream_.read(reinterpret_cast<char*>(&info.flags), sizeof(info.flags));
      uint16_t reason_length = 0;
      stream_.read(reinterpret_cast<char*>(&reason_length), sizeof(reason_length));
      if (!stream_.good()) {
        return false;
      }
      if (reason_length > 0) {
        info.reason.resize(reason_length);
        stream_.read(info.reason.data(), reason_length);
        if (!stream_.good()) {
          return false;
        }
      }
      event.boundary = std::move(info);
    } else {
      event.boundary.reset();
    }
  } else {
    event.boundary.reset();
  }

  return true;
}

bool binary_trace_source::read_registers(trace_event& event) {
  uint32_t count = 0;
  stream_.read(reinterpret_cast<char*>(&count), sizeof(count));
  if (!stream_.good()) {
    return false;
  }

  event.registers.clear();
  event.registers.reserve(count);

  for (uint32_t i = 0; i < count; ++i) {
    uint16_t name_len = 0;
    stream_.read(reinterpret_cast<char*>(&name_len), sizeof(name_len));
    if (!stream_.good()) {
      return false;
    }

    std::string name(name_len, '\0');
    stream_.read(name.data(), name_len);
    if (!stream_.good()) {
      return false;
    }

    uint64_t value = 0;
    stream_.read(reinterpret_cast<char*>(&value), sizeof(value));
    if (!stream_.good()) {
      return false;
    }

    event.registers.push_back(trace_register_delta{name, value});
  }

  return true;
}

bool binary_trace_source::read_memory_list(std::vector<trace_memory_delta>& accesses) {
  uint32_t count = 0;
  stream_.read(reinterpret_cast<char*>(&count), sizeof(count));
  if (!stream_.good()) {
    return false;
  }

  accesses.clear();
  accesses.reserve(count);

  for (uint32_t i = 0; i < count; ++i) {
    trace_memory_delta delta;
    stream_.read(reinterpret_cast<char*>(&delta.address), sizeof(delta.address));
    stream_.read(reinterpret_cast<char*>(&delta.size), sizeof(delta.size));
    uint8_t known = 0;
    stream_.read(reinterpret_cast<char*>(&known), sizeof(known));
    delta.value_known = known != 0;
    uint32_t data_size = 0;
    stream_.read(reinterpret_cast<char*>(&data_size), sizeof(data_size));
    if (!stream_.good()) {
      return false;
    }

    delta.data.resize(data_size);
    if (data_size > 0) {
      stream_.read(reinterpret_cast<char*>(delta.data.data()), data_size);
      if (!stream_.good()) {
        return false;
      }
    }

    accesses.push_back(std::move(delta));
  }

  return true;
}

} // namespace w1::rewind
