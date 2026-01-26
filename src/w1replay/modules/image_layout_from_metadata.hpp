#pragma once

#include <string>

#include "image_bytes.hpp"
#include "w1rewind/format/trace_format.hpp"

namespace w1replay {

bool build_layout_from_metadata(
    const w1::rewind::image_metadata_record& meta,
    const std::string& path,
    image_layout& layout,
    std::string& error
);

} // namespace w1replay
