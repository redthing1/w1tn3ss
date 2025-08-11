#pragma once

#include "ext/args.hpp"

namespace w1tool::commands {

int insert_library(
    args::Positional<std::string>& dylib_path,
    args::Positional<std::string>& binary_path,
    args::Positional<std::string>& output_path,
    args::Flag& inplace,
    args::Flag& weak,
    args::Flag& overwrite,
    args::Flag& strip_codesig,
    args::Flag& all_yes
);

} // namespace w1tool::commands