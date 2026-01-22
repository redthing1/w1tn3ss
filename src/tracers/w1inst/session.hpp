#pragma once

#include "w1instrument/tracer/vm_session.hpp"

#include "instruction_tracer.hpp"

namespace w1inst {

using session = w1::vm_session<instruction_tracer>;

} // namespace w1inst
