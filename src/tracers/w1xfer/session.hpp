#pragma once

#include "w1instrument/tracer/trace_session.hpp"

#include "transfer_tracer.hpp"

namespace w1xfer {

using session = w1::trace_session<transfer_tracer>;

} // namespace w1xfer
