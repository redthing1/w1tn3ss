#pragma once

#include "w1instrument/tracer/trace_session.hpp"

#include "coverage_tracer.hpp"

namespace w1cov {

using coverage_block_session = w1::trace_session<coverage_tracer<coverage_mode::basic_block>>;
using coverage_inst_session = w1::trace_session<coverage_tracer<coverage_mode::instruction>>;

} // namespace w1cov
