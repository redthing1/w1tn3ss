#pragma once

#include "types.hpp"
#include <string>

namespace p1ll::core {

// compile signature pattern from hex string with wildcards
compiled_signature compile_signature(const signature_pattern& pattern);

// compile patch pattern from hex string
compiled_patch compile_patch(const patch_pattern& pattern);

// validate signature pattern syntax
bool validate_signature_pattern(const signature_pattern& pattern);

// validate patch pattern syntax
bool validate_patch_pattern(const patch_pattern& pattern);

// utility to create signature queries
signature_query create_signature_query(const signature_pattern& pattern, const signature_query_filter& filter = {});

} // namespace p1ll::core