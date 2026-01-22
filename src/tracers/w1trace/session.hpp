#pragma once

#include \"w1instrument/tracer/vm_session.hpp\"

#include \"trace_tracer.hpp\"

namespace w1trace {

using session = w1::vm_session<trace_tracer>;

} // namespace w1trace
