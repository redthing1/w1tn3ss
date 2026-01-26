#include "darwin_loaded_libraries.hpp"

#include "w1rewind/replay/replay_context.hpp"
#include "w1rewind/replay/mapping_state.hpp"

#include <algorithm>
#include <cstdio>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace w1replay::gdb {

namespace {
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

const w1::rewind::mapping_range* find_range_for_address(
    const w1::rewind::mapping_state* mappings, uint32_t space_id, uint64_t address
) {
  if (!mappings) {
    return nullptr;
  }
  auto it = mappings->ranges_by_space().find(space_id);
  if (it == mappings->ranges_by_space().end() || it->second.empty()) {
    return nullptr;
  }
  const auto& ranges = it->second;
  auto upper = std::upper_bound(ranges.begin(), ranges.end(), address, [](uint64_t value, const auto& range) {
    return value < range.start;
  });
  if (upper == ranges.begin()) {
    return nullptr;
  }
  --upper;
  if (address >= upper->end) {
    return nullptr;
  }
  return &*upper;
}
} // namespace

darwin_loaded_libraries_provider::darwin_loaded_libraries_provider(
    const w1::rewind::replay_context& context, const w1::rewind::mapping_state* mappings,
    image_metadata_provider& metadata_provider, image_path_resolver& resolver
)
    : context_(context), mappings_(mappings), metadata_provider_(metadata_provider), resolver_(resolver) {}

std::vector<darwin_loaded_image> darwin_loaded_libraries_provider::collect_loaded_images(
    const gdbstub::lldb::loaded_libraries_request& request
) const {
  std::unordered_set<uint64_t> filter;
  if (request.kind == gdbstub::lldb::loaded_libraries_request::kind::addresses) {
    filter.insert(request.addresses.begin(), request.addresses.end());
  }

  std::unordered_map<uint64_t, uint64_t> image_bases;
  if (mappings_) {
    auto it = mappings_->ranges_by_space().find(0);
    if (it != mappings_->ranges_by_space().end()) {
      for (const auto& range : it->second) {
        if (!range.mapping || range.end <= range.start) {
          continue;
        }
        if (range.mapping->image_id == 0) {
          continue;
        }
        auto base_it = image_bases.find(range.mapping->image_id);
        if (base_it == image_bases.end() || range.start < base_it->second) {
          image_bases[range.mapping->image_id] = range.start;
        }
      }
    }
  } else {
    for (const auto& mapping : context_.mappings) {
      if (mapping.space_id != 0 || mapping.image_id == 0 || mapping.size == 0) {
        continue;
      }
      auto it = image_bases.find(mapping.image_id);
      if (it == image_bases.end() || mapping.base < it->second) {
        image_bases[mapping.image_id] = mapping.base;
      }
    }
  }

  bool include_load_commands = request.report_load_commands;
  std::vector<darwin_loaded_image> images;
  images.reserve(context_.images.size());

  for (const auto& image : context_.images) {
    auto base_it = image_bases.find(image.image_id);
    if (base_it == image_bases.end()) {
      continue;
    }
    if (!filter.empty() && filter.find(base_it->second) == filter.end()) {
      continue;
    }

    darwin_loaded_image loaded{};
    loaded.load_address = base_it->second;
    if (auto resolved = resolver_.resolve_image_path(image)) {
      loaded.pathname = *resolved;
    } else if (!image.identity.empty()) {
      loaded.pathname = image.identity;
    } else if (!image.name.empty()) {
      loaded.pathname = image.name;
    }

    std::string error;
    auto uuid = metadata_provider_.image_uuid(image, error);
    if (uuid) {
      loaded.uuid = *uuid;
    }

    if (include_load_commands) {
      auto header = metadata_provider_.macho_header(image, error);
      if (header) {
        loaded.header = *header;
      }
      auto segments = metadata_provider_.macho_segments(image, error);
      if (!segments.empty()) {
        loaded.segments = std::move(segments);
      }
    }

    images.push_back(std::move(loaded));
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

  const w1::rewind::mapping_record* mapping = nullptr;
  uint64_t mapping_base = 0;
  uint64_t mapping_offset = 0;
  if (mappings_) {
    if (const auto* range = find_range_for_address(mappings_, 0, *current_pc)) {
      mapping = range->mapping;
      mapping_base = range->start;
    }
  }
  if (!mapping) {
    mapping = context_.find_mapping_for_address(0, *current_pc, 1, mapping_offset);
    if (mapping) {
      mapping_base = mapping->base;
    }
  }
  if (!mapping) {
    return extras;
  }
  const auto* image = context_.find_image(mapping->image_id);
  if (!image) {
    return extras;
  }

  gdbstub::lldb::process_kv_pair addr{};
  addr.key = "main-binary-address";
  addr.u64_value = mapping_base;
  addr.encoding = gdbstub::lldb::kv_encoding::hex_u64;
  extras.push_back(std::move(addr));

  std::string uuid_error;
  auto uuid = metadata_provider_.image_uuid(*image, uuid_error);
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
