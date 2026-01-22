#pragma once

#include "w1instrument/tracer/vm_session.hpp"

#include "transfer_recorder.hpp"

namespace w1xfer {

using session = w1::vm_session<transfer_recorder>;

} // namespace w1xfer
