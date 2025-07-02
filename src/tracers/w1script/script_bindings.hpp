#pragma once

#ifdef WITNESS_SCRIPT_ENABLED

#include <sol/sol.hpp>
#include <QBDI.h>

namespace w1::tracers::script {

void setup_qbdi_bindings(sol::state& lua);

} // namespace w1::tracers::script

#endif // WITNESS_SCRIPT_ENABLED