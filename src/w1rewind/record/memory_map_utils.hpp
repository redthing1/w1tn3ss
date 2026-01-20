#pragma once

#include <vector>

#include "w1rewind/format/trace_format.hpp"

namespace w1::rewind {

void assign_memory_map_image_ids(
    std::vector<memory_region_record>& regions, const std::vector<module_record>& modules
);

} // namespace w1::rewind
