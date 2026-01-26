#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace w1::rewind {
struct image_record;
}

namespace w1replay {

struct macho_header_info {
  uint32_t magic = 0;
  uint32_t cputype = 0;
  uint32_t cpusubtype = 0;
  uint32_t filetype = 0;
};

struct macho_segment_info {
  std::string name;
  uint64_t vmaddr = 0;
  uint64_t vmsize = 0;
  uint64_t fileoff = 0;
  uint64_t filesize = 0;
  uint32_t maxprot = 0;
};

class image_metadata_provider {
public:
  virtual ~image_metadata_provider() = default;

  virtual std::optional<std::string> image_uuid(const w1::rewind::image_record& image, std::string& error) = 0;
  virtual std::optional<macho_header_info> macho_header(
      const w1::rewind::image_record& image, std::string& error
  ) = 0;
  virtual std::vector<macho_segment_info> macho_segments(
      const w1::rewind::image_record& image, std::string& error
  ) = 0;
};

} // namespace w1replay
