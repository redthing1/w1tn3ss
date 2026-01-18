#pragma once

#include "w1base/ext/args.hpp"
#include <string>

namespace w1tool::commands {

int read_dump(
    args::ValueFlag<std::string>& file_flag, args::Flag& detailed_flag, args::ValueFlag<std::string>& module_flag
);

} // namespace w1tool::commands