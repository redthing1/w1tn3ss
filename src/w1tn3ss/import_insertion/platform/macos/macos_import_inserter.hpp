#pragma once

#include "../../import_insertion.hpp"

namespace w1::import_insertion::macos {

// wrapper around the macos backend implementation
result insert_library_import(const config& cfg);

// capabilities check
bool check_import_capabilities();

} // namespace w1::import_insertion::macos