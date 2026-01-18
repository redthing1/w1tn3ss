#pragma once

#include "w1import/import_insertion.hpp"

namespace w1::import_insertion::linux_impl {

// stub implementation for linux platform
result insert_library_import(const config& cfg);

// capabilities check
bool check_import_capabilities();

} // namespace w1::import_insertion::linux_impl