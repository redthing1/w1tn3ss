#include "trace_metadata_provider.hpp"

namespace w1replay {

trace_image_metadata_provider::trace_image_metadata_provider(const w1::rewind::replay_context* context)
    : context_(context) {}

std::optional<std::string> trace_image_metadata_provider::image_uuid(
    const w1::rewind::image_record& image, std::string& error
) {
  error.clear();
  const w1::rewind::image_metadata_record* meta = nullptr;
  if (context_) {
    meta = context_->find_image_metadata(image.image_id);
  }
  if (meta && (meta->flags & w1::rewind::image_meta_has_uuid) != 0 && !meta->uuid.empty()) {
    return meta->uuid;
  }

  std::string format = image.kind;
  if (meta && !meta->format.empty()) {
    format = meta->format;
  }
  if (!image.identity.empty() && format == "macho") {
    return image.identity;
  }

  return std::nullopt;
}

std::optional<macho_header_info> trace_image_metadata_provider::macho_header(
    const w1::rewind::image_record& image, std::string& error
) {
  error.clear();
  if (context_) {
    auto* meta = context_->find_image_metadata(image.image_id);
    if (meta && (meta->flags & w1::rewind::image_meta_has_macho_header) != 0) {
      const auto& header = meta->macho_header;
      macho_header_info info{};
      info.magic = header.magic;
      info.cputype = header.cputype;
      info.cpusubtype = header.cpusubtype;
      info.filetype = header.filetype;
      return info;
    }
  }
  return std::nullopt;
}

std::vector<macho_segment_info> trace_image_metadata_provider::macho_segments(
    const w1::rewind::image_record& image, std::string& error
) {
  error.clear();
  if (context_) {
    auto* meta = context_->find_image_metadata(image.image_id);
    if (meta && (meta->flags & w1::rewind::image_meta_has_segments) != 0) {
      std::vector<macho_segment_info> segments;
      segments.reserve(meta->segments.size());
      for (const auto& segment : meta->segments) {
        macho_segment_info info{};
        info.name = segment.name;
        info.vmaddr = segment.vmaddr;
        info.vmsize = segment.vmsize;
        info.fileoff = segment.fileoff;
        info.filesize = segment.filesize;
        info.maxprot = segment.maxprot;
        segments.push_back(std::move(info));
      }
      return segments;
    }
  }
  return {};
}

} // namespace w1replay
