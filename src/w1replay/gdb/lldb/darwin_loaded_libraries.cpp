#include "darwin_loaded_libraries.hpp"

#include <cstdio>
#include <string_view>
#include <unordered_set>

namespace w1replay::gdb {

namespace {
std::optional<std::string> uuid_from_record(const w1::rewind::module_record& module) {
  if (module.format != w1::rewind::module_format::macho) {
    return std::nullopt;
  }
  if (module.identity.empty()) {
    return std::nullopt;
  }
  return module.identity;
}

void append_json_string(std::string& out, std::string_view value) {
  out.push_back('"');
  for (char ch : value) {
    switch (ch) {
    case '"':
      out += "\\\"";
      break;
    case '\\':
      out += "\\\\";
      break;
    case '\b':
      out += "\\b";
      break;
    case '\f':
      out += "\\f";
      break;
    case '\n':
      out += "\\n";
      break;
    case '\r':
      out += "\\r";
      break;
    case '\t':
      out += "\\t";
      break;
    default:
      if (static_cast<unsigned char>(ch) < 0x20) {
        char buf[7];
        std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned int>(static_cast<unsigned char>(ch)));
        out += buf;
      } else {
        out.push_back(ch);
      }
      break;
    }
  }
  out.push_back('"');
}

void append_json_key(std::string& out, std::string_view key) {
  append_json_string(out, key);
  out.push_back(':');
}
} // namespace

darwin_loaded_libraries_provider::darwin_loaded_libraries_provider(
    const w1::rewind::replay_context& context, module_source& module_source
)
    : context_(context), module_source_(module_source) {}

std::vector<darwin_loaded_image> darwin_loaded_libraries_provider::collect_loaded_images(
    const gdbstub::lldb::loaded_libraries_request& request
) const {
  std::unordered_set<uint64_t> filter;
  if (request.kind == gdbstub::lldb::loaded_libraries_request::kind::addresses) {
    filter.insert(request.addresses.begin(), request.addresses.end());
  }

  bool include_load_commands = request.report_load_commands;
  std::vector<darwin_loaded_image> images;
  const auto& modules = context_.modules;
  images.reserve(modules.size());

  for (const auto& module : modules) {
    if (!filter.empty() && filter.find(module.base) == filter.end()) {
      continue;
    }

    darwin_loaded_image image{};
    image.load_address = module.base;
    image.pathname = module.path;

    std::string error;
    auto uuid = uuid_from_record(module);
    if (!uuid && !module.path.empty()) {
      uuid = module_source_.get_module_uuid(module, error);
    }
    if (uuid.has_value()) {
      image.uuid = *uuid;
    }

    if (include_load_commands) {
      if (!module.path.empty()) {
        auto header = module_source_.get_macho_header_info(module, error);
        if (header) {
          image.header = *header;
        }
        auto segments = module_source_.get_macho_segments(module, error);
        if (!segments.empty()) {
          image.segments = std::move(segments);
        }
      }
    }

    images.push_back(std::move(image));
  }

  return images;
}

std::string build_darwin_loaded_libraries_json(
    const std::vector<darwin_loaded_image>& images, const gdbstub::lldb::loaded_libraries_request& request
) {
  std::string json;
  json.reserve(256 * (images.size() + 1));
  json += "{\"images\":[";
  for (size_t i = 0; i < images.size(); ++i) {
    if (i > 0) {
      json += ",";
    }
    json += "{";
    append_json_key(json, "load_address");
    json += std::to_string(images[i].load_address);
    json += ",\"mod_date\":0";
    if (!images[i].pathname.empty()) {
      json += ",";
      append_json_key(json, "pathname");
      append_json_string(json, images[i].pathname);
    }
    if (images[i].uuid.has_value()) {
      json += ",";
      append_json_key(json, "uuid");
      append_json_string(json, *images[i].uuid);
    }
    if (request.report_load_commands && images[i].header.has_value()) {
      const auto& header = *images[i].header;
      json += ",\"mach_header\":{";
      append_json_key(json, "magic");
      json += std::to_string(header.magic);
      json += ",";
      append_json_key(json, "cputype");
      json += std::to_string(header.cputype);
      json += ",";
      append_json_key(json, "cpusubtype");
      json += std::to_string(header.cpusubtype);
      json += ",";
      append_json_key(json, "filetype");
      json += std::to_string(header.filetype);
      json += "}";

      json += ",\"segments\":[";
      for (size_t j = 0; j < images[i].segments.size(); ++j) {
        if (j > 0) {
          json += ",";
        }
        const auto& segment = images[i].segments[j];
        json += "{";
        append_json_key(json, "name");
        append_json_string(json, segment.name);
        json += ",";
        append_json_key(json, "vmaddr");
        json += std::to_string(segment.vmaddr);
        json += ",";
        append_json_key(json, "vmsize");
        json += std::to_string(segment.vmsize);
        json += ",";
        append_json_key(json, "fileoff");
        json += std::to_string(segment.fileoff);
        json += ",";
        append_json_key(json, "filesize");
        json += std::to_string(segment.filesize);
        json += ",";
        append_json_key(json, "maxprot");
        json += std::to_string(segment.maxprot);
        json += "}";
      }
      json += "]";
    }
    json += "}";
  }
  json += "]}";
  return json;
}

std::optional<std::string> darwin_loaded_libraries_provider::loaded_libraries_json(
    const gdbstub::lldb::loaded_libraries_request& request
) {
  auto images = collect_loaded_images(request);
  return build_darwin_loaded_libraries_json(images, request);
}

std::optional<std::vector<gdbstub::lldb::process_kv_pair>> darwin_loaded_libraries_provider::process_info_extras(
    std::optional<uint64_t> current_pc
) const {
  std::vector<gdbstub::lldb::process_kv_pair> extras;
  if (!current_pc.has_value()) {
    return extras;
  }

  uint64_t module_offset = 0;
  auto* module = context_.find_module_for_address(*current_pc, 1, module_offset);
  if (!module || module->path.empty()) {
    return extras;
  }

  gdbstub::lldb::process_kv_pair addr{};
  addr.key = "main-binary-address";
  addr.u64_value = module->base;
  addr.encoding = gdbstub::lldb::kv_encoding::hex_u64;
  extras.push_back(std::move(addr));

  std::string uuid_error;
  auto uuid = uuid_from_record(*module);
  if (!uuid) {
    uuid = module_source_.get_module_uuid(*module, uuid_error);
  }
  if (uuid) {
    gdbstub::lldb::process_kv_pair uuid_pair{};
    uuid_pair.key = "main-binary-uuid";
    uuid_pair.value = *uuid;
    uuid_pair.encoding = gdbstub::lldb::kv_encoding::raw;
    extras.push_back(std::move(uuid_pair));
  }

  return extras;
}

bool darwin_loaded_libraries_provider::has_loaded_images() const {
  gdbstub::lldb::loaded_libraries_request request{};
  request.kind = gdbstub::lldb::loaded_libraries_request::kind::all;
  return !collect_loaded_images(request).empty();
}

} // namespace w1replay::gdb
