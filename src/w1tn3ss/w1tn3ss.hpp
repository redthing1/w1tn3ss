#pragma once

#include "util/log.hpp"

namespace w1 {

class w1tn3ss {
public:
    w1tn3ss();
    ~w1tn3ss();
    
    // Main analysis interface - to be implemented
    bool initialize();
    void shutdown();
};

} // namespace w1