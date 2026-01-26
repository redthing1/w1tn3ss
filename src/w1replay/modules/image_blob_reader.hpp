#pragma once

#include <cstddef>
#include <cstdint>

#include "image_bytes.hpp"
#include "w1rewind/replay/image_blob_index.hpp"

namespace w1replay {

image_read_result read_image_blob_index(
    const w1::rewind::image_blob_index& index, uint64_t image_offset, size_t size
);

} // namespace w1replay
