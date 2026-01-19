#pragma once

#include <cstdint>
#include <optional>
#include <unordered_set>

#include "gdbstub/target.hpp"

#include "w1rewind/replay/replay_session.hpp"

#include "run_policy.hpp"

namespace w1replay::gdb {

struct stepper_result {
  gdbstub::resume_result resume;
  std::optional<gdbstub::stop_reason> last_stop;
};

stepper_result resume_step(
    w1::rewind::replay_session& session, const run_policy& policy, const std::unordered_set<uint64_t>& breakpoints,
    uint64_t thread_id, gdbstub::resume_direction direction
);

stepper_result resume_continue(
    w1::rewind::replay_session& session, const run_policy& policy, const std::unordered_set<uint64_t>& breakpoints,
    uint64_t thread_id, gdbstub::resume_direction direction
);

} // namespace w1replay::gdb
