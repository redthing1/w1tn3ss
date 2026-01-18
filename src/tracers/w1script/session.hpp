#pragma once

#include "w1instrument/tracer/trace_session.hpp"

#include "script_tracer.hpp"

namespace w1::tracers::script {

using script_session = w1::trace_session<script_tracer>;

} // namespace w1::tracers::script
