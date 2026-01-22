#pragma once

#include <memory>

#include "w1h00k/backend/backend.hpp"

namespace w1::h00k::backend {

std::unique_ptr<hook_backend> make_interpose_backend();

} // namespace w1::h00k::backend
