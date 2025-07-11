#pragma once

#include "types.hpp"
#include "utils/hex_pattern.hpp"

#include <string>
#include <optional>

namespace p1ll {

// compile signature pattern from hex string with wildcards
std::optional<compiled_signature> compile_signature(const signature_pattern& pattern);

// pattern visualization
std::string format_compiled_signature(const compiled_signature& sig);

// compile patch pattern from hex string
std::optional<compiled_patch> compile_patch(const patch_pattern& pattern);

// validate signature pattern syntax
bool validate_signature_pattern(const signature_pattern& pattern);

// validate patch pattern syntax
bool validate_patch_pattern(const patch_pattern& pattern);

// utility to create signature queries
std::optional<signature_query> create_signature_query(
    const signature_pattern& pattern, const signature_query_filter& filter = {}
);

} // namespace p1ll