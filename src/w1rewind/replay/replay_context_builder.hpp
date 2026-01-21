#pragma once

#include <string>

#include "replay_context.hpp"
#include "w1rewind/trace/record_stream.hpp"

namespace w1::rewind {

bool build_replay_context(trace_record_stream& stream, replay_context& out, std::string& error);

} // namespace w1::rewind
