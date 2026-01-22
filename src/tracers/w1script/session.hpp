#pragma once

#include "w1instrument/tracer/vm_session.hpp"

#include "script_tracer.hpp"

namespace w1::tracers::script {

using script_session = w1::vm_session<script_tracer>;

} // namespace w1::tracers::script
