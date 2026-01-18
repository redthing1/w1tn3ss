#pragma once

#include "module_image.hpp"

#if defined(WITNESS_LIEF_ENABLED)
#include <LIEF/LIEF.hpp>
#include <string>

namespace w1replay {

bool build_image_layout(const LIEF::Binary& binary, image_layout& layout, std::string& error);

} // namespace w1replay
#endif
