#if defined(__APPLE__)
#define _XOPEN_SOURCE 700
#endif

#include "instraware_common.hpp"

#include <cstdint>
#include <string>

#if defined(_WIN32)
#include <windows.h>
#else
#include <signal.h>
#include <ucontext.h>
#endif

#if defined(__APPLE__) && defined(__aarch64__)
#include <ptrauth.h>
#endif

namespace {

static volatile uintptr_t g_expected_pc = 0;
static volatile uintptr_t g_expected_next_pc = 0;
static volatile uintptr_t g_observed_pc = 0;
static volatile bool g_faulted = false;

uintptr_t strip_pac(uintptr_t value) {
#if defined(__APPLE__) && defined(__aarch64__) && defined(__has_feature)
#if __has_feature(ptrauth_calls)
  return reinterpret_cast<uintptr_t>(ptrauth_strip(reinterpret_cast<void*>(value), ptrauth_key_return_address));
#endif
#endif
  return value;
}

#if !defined(_WIN32)
#if (defined(__APPLE__) || defined(__linux__)) && (defined(__x86_64__) || defined(__aarch64__))
#define INSTRAWARE_HAVE_UCONTEXT_PC 1
#else
#define INSTRAWARE_HAVE_UCONTEXT_PC 0
#endif

#if INSTRAWARE_HAVE_UCONTEXT_PC
uintptr_t extract_pc(void* ctx_ptr) {
  auto* ctx = reinterpret_cast<ucontext_t*>(ctx_ptr);
#if defined(__APPLE__)
#if defined(__x86_64__)
  return static_cast<uintptr_t>(ctx->uc_mcontext->__ss.__rip);
#elif defined(__aarch64__)
  return static_cast<uintptr_t>(ctx->uc_mcontext->__ss.__pc);
#else
  return 0;
#endif
#elif defined(__linux__)
#if defined(__x86_64__)
  return static_cast<uintptr_t>(ctx->uc_mcontext.gregs[REG_RIP]);
#elif defined(__aarch64__)
  return static_cast<uintptr_t>(ctx->uc_mcontext.pc);
#else
  return 0;
#endif
#else
  return 0;
#endif
}

bool set_pc(void* ctx_ptr, uintptr_t pc) {
  auto* ctx = reinterpret_cast<ucontext_t*>(ctx_ptr);
#if defined(__APPLE__)
#if defined(__x86_64__)
  ctx->uc_mcontext->__ss.__rip = static_cast<uint64_t>(pc);
  return true;
#elif defined(__aarch64__)
  ctx->uc_mcontext->__ss.__pc = static_cast<uint64_t>(pc);
  return true;
#else
  (void) ctx;
  (void) pc;
  return false;
#endif
#elif defined(__linux__)
#if defined(__x86_64__)
  ctx->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(pc);
  return true;
#elif defined(__aarch64__)
  ctx->uc_mcontext.pc = static_cast<unsigned long long>(pc);
  return true;
#else
  (void) ctx;
  (void) pc;
  return false;
#endif
#else
  (void) ctx;
  (void) pc;
  return false;
#endif
}
#else
uintptr_t extract_pc(void*) { return 0; }

bool set_pc(void*, uintptr_t) { return false; }
#endif

void fault_handler(int sig, siginfo_t*, void* ctx) {
  (void) sig;
  g_observed_pc = extract_pc(ctx);
  g_faulted = true;
  uintptr_t resume = static_cast<uintptr_t>(g_expected_next_pc);
  if (resume != 0) {
    set_pc(ctx, resume);
  }
}
#endif

void trigger_fault() {
#if defined(__GNUC__) || defined(__clang__)
  g_expected_pc = reinterpret_cast<uintptr_t>(&&fault_label);
  g_expected_next_pc = reinterpret_cast<uintptr_t>(&&after_fault);
fault_label:
#if defined(__x86_64__) || defined(_M_X64)
  asm volatile("int3");
#elif defined(__aarch64__) || defined(_M_ARM64)
  asm volatile("brk #0");
#else
  __builtin_trap();
#endif
after_fault:
  asm volatile("" ::: "memory");
#else
#if defined(_WIN32)
  __debugbreak();
#else
  __builtin_trap();
#endif
#endif
}

} // namespace

#if defined(_WIN32)
void run_fault_probe() {
  EXCEPTION_POINTERS* info = nullptr;
  __try {
    trigger_fault();
  } __except ((info = GetExceptionInformation()), EXCEPTION_EXECUTE_HANDLER) {
#if defined(_M_X64)
    if (info && info->ContextRecord) {
      g_observed_pc = static_cast<uintptr_t>(info->ContextRecord->Rip);
    }
#elif defined(_M_ARM64)
    if (info && info->ContextRecord) {
      g_observed_pc = static_cast<uintptr_t>(info->ContextRecord->Pc);
    }
#endif
    g_faulted = true;
  }
}
#endif

int main(int argc, char** argv) {
  instraware::args args = instraware::parse_args(argc, argv);
  instraware::result result;
  result.test_id = "fault";
  result.platform = instraware::platform();
  result.arch = instraware::arch();

  FILE* out = instraware::open_output(args.json_out);

#if defined(_WIN32)
  bool have_expected = false;
  run_fault_probe();

  result.iterations = 0;
  result.anomalies = 0;
  result.score = 0.0;
  result.confidence = 0.3;
  result.notes = have_expected ? "fault_checked" : "fault_subtest_skipped: no portable fault label on msvc";
  instraware::emit_json(result, out);
  instraware::close_output(out);
  return 0;
#else
#if !INSTRAWARE_HAVE_UCONTEXT_PC
  result.iterations = 0;
  result.anomalies = 0;
  result.score = 0.0;
  result.confidence = 0.3;
  result.notes = "fault_subtest_skipped: unsupported ucontext pc";
  instraware::emit_json(result, out);
  instraware::close_output(out);
  return 0;
#endif

#if !defined(__GNUC__) && !defined(__clang__)
  result.iterations = 0;
  result.anomalies = 0;
  result.score = 0.0;
  result.confidence = 0.3;
  result.notes = "fault_subtest_skipped: no label support";
  instraware::emit_json(result, out);
  instraware::close_output(out);
  return 0;
#endif

  struct sigaction sa{};
  sa.sa_sigaction = fault_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  sigaction(SIGTRAP, &sa, nullptr);
  sigaction(SIGILL, &sa, nullptr);

  g_faulted = false;
  g_observed_pc = 0;
  g_expected_pc = 0;
  g_expected_next_pc = 0;
  trigger_fault();

  uintptr_t expected = strip_pac(static_cast<uintptr_t>(g_expected_pc));
  uintptr_t expected_next = strip_pac(static_cast<uintptr_t>(g_expected_next_pc));
  uintptr_t observed = strip_pac(static_cast<uintptr_t>(g_observed_pc));
  bool have_expected = expected != 0 && expected_next != 0;
  bool mismatch = have_expected && g_faulted && (observed != expected && observed != expected_next);
  bool missing_fault = have_expected && !g_faulted;

  result.iterations = have_expected ? 1 : 0;
  result.anomalies = (mismatch || missing_fault) ? 1 : 0;
  result.score = result.anomalies ? 1.0 : 0.0;
  result.confidence = have_expected ? 0.8 : 0.3;
  std::string notes = have_expected ? "fault_checked" : "fault_subtest_skipped: no label support";
  if (have_expected && missing_fault) {
    notes += ";fault_missing";
  } else if (have_expected && mismatch) {
    notes += ";fault_pc_mismatch";
  }
  result.notes = notes;

  instraware::emit_json(result, out);
  instraware::close_output(out);
  return 0;
#endif
}
