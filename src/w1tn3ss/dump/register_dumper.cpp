#include "register_dumper.hpp"
#include <thread>
#include <sstream>
#include <iomanip>

namespace w1 {
namespace dump {

redlog::logger register_dumper::log_ = redlog::get_logger("w1.dump.register");

thread_state register_dumper::capture_thread_state(const QBDI::GPRState& gpr, const QBDI::FPRState& fpr) {
  log_.vrb("capturing thread state");

  thread_state state;

  // get current thread id
  auto thread_id = std::this_thread::get_id();
  std::stringstream ss;
  ss << thread_id;
  state.thread_id = std::stoull(ss.str());

  // convert gpr state to vector
  // gprstate is an array of rword (uint32_t or uint64_t depending on arch)
  const size_t gpr_count = sizeof(QBDI::GPRState) / sizeof(QBDI::rword);
  const QBDI::rword* gpr_array = reinterpret_cast<const QBDI::rword*>(&gpr);
  state.gpr_values.assign(gpr_array, gpr_array + gpr_count);

  // convert fpr state to vector
  // fprstate size varies by architecture
#if defined(QBDI_ARCH_X86_64) || defined(QBDI_ARCH_X86)
  // x86/x64 has mmx and xmm registers
  const size_t fpr_size = sizeof(QBDI::FPRState);
  const uint64_t* fpr_array = reinterpret_cast<const uint64_t*>(&fpr);
  const size_t fpr_count = fpr_size / sizeof(uint64_t);
  state.fpr_values.assign(fpr_array, fpr_array + fpr_count);
#elif defined(QBDI_ARCH_AARCH64)
  // aarch64 has vector registers
  const size_t fpr_size = sizeof(QBDI::FPRState);
  const uint64_t* fpr_array = reinterpret_cast<const uint64_t*>(&fpr);
  const size_t fpr_count = fpr_size / sizeof(uint64_t);
  state.fpr_values.assign(fpr_array, fpr_array + fpr_count);
#else
  // other architectures may not have fpr
  log_.dbg("fpr state not captured for this architecture");
#endif

  log_.trc(
      "captured thread state", redlog::field("thread_id", state.thread_id),
      redlog::field("gpr_count", state.gpr_values.size()), redlog::field("fpr_count", state.fpr_values.size())
  );

  return state;
}

} // namespace dump
} // namespace w1