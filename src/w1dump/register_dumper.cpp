#include "w1dump/register_dumper.hpp"

#include <cstddef>

namespace w1::dump {

redlog::logger register_dumper::log_ = redlog::get_logger("w1.dump.register");

thread_state register_dumper::capture_thread_state(
    const QBDI::GPRState& gpr, const QBDI::FPRState& fpr, uint64_t thread_id
) {
  log_.vrb("capturing thread state");

  thread_state state;
  state.thread_id = thread_id;

  const size_t gpr_count = sizeof(QBDI::GPRState) / sizeof(QBDI::rword);
  const QBDI::rword* gpr_array = reinterpret_cast<const QBDI::rword*>(&gpr);
  state.gpr_values.assign(gpr_array, gpr_array + gpr_count);

#if defined(QBDI_ARCH_X86_64) || defined(QBDI_ARCH_X86) || defined(QBDI_ARCH_AARCH64)
  const size_t fpr_size = sizeof(QBDI::FPRState);
  const uint64_t* fpr_array = reinterpret_cast<const uint64_t*>(&fpr);
  const size_t fpr_count = fpr_size / sizeof(uint64_t);
  state.fpr_values.assign(fpr_array, fpr_array + fpr_count);
#endif

  log_.trc(
      "captured thread state", redlog::field("thread_id", state.thread_id),
      redlog::field("gpr_count", state.gpr_values.size()), redlog::field("fpr_count", state.fpr_values.size())
  );

  return state;
}

} // namespace w1::dump
