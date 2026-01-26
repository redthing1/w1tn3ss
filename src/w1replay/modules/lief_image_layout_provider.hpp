#pragma once

#include <memory>
#include <string>

#include "image_layout_provider.hpp"

namespace w1replay {

std::shared_ptr<image_layout_provider> make_lief_layout_provider(std::string& error);

} // namespace w1replay
