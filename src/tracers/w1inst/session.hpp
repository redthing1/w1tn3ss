#pragma once

#include "w1tn3ss/tracer/trace_session.hpp"

#include "instruction_tracer.hpp"

namespace w1inst {

using session = w1::trace_session<instruction_tracer>;

} // namespace w1inst
