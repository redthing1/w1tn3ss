#pragma once

#include "ext/args.hpp"
#include <string>

namespace w1tool::commands {

int dump(
    args::ValueFlag<std::string>& library_flag, args::Flag& spawn_flag, args::ValueFlag<int>& pid_flag,
    args::ValueFlag<std::string>& name_flag, args::ValueFlag<std::string>& output_flag, args::Flag& memory_flag,
    args::ValueFlagList<std::string>& filter_flag, args::ValueFlag<std::string>& max_region_size_flag,
    args::ValueFlag<int>& debug_level_flag, args::Flag& suspended_flag, args::Flag& no_aslr_flag,
    args::PositionalList<std::string>& args_list, const std::string& executable_path
);

} // namespace w1tool::commands