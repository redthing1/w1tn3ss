#pragma once

#include <redlog/redlog.hpp>

namespace w1 {

class w1tn3ss {
public:
    w1tn3ss();
    ~w1tn3ss();
    
    bool initialize();
    void shutdown();

private:
    redlog::logger log_;
};

} // namespace w1