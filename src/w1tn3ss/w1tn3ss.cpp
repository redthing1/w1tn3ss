#include "w1tn3ss.hpp"

namespace w1 {

w1tn3ss::w1tn3ss() {
    util::log_info("w1tn3ss initialized");
}

w1tn3ss::~w1tn3ss() {
    util::log_info("w1tn3ss destroyed");
}

bool w1tn3ss::initialize() {
    util::log_info("w1tn3ss::initialize() called");
    return true;
}

void w1tn3ss::shutdown() {
    util::log_info("w1tn3ss::shutdown() called");
}

} // namespace w1