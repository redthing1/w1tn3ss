#pragma once

#include "ext/args.hpp"

namespace w1tool::commands {

int debug(
    args::ValueFlag<int>& pid_flag, args::Flag& spawn_flag, args::Flag& interactive_flag, args::Flag& suspended_flag,
    args::PositionalList<std::string>& args_list
);

} // namespace w1tool::commands
