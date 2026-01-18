#pragma once

#include \"w1instrument/tracer/trace_session.hpp\"

#include \"trace_tracer.hpp\"

namespace w1trace {

using session = w1::trace_session<trace_tracer>;

} // namespace w1trace
