#include "instraware_common.hpp"

#include <cstdint>
#include <cstring>
#include <string>

#if defined(_WIN32)
#include <intrin.h>
#include <windows.h>
#endif

namespace {

#if defined(_MSC_VER)
#define INSTRAWARE_NOINLINE __declspec(noinline)
#else
#define INSTRAWARE_NOINLINE __attribute__((noinline))
#endif

uintptr_t read_sp() {
#if defined(__x86_64__) || defined(_M_X64)
#if defined(_MSC_VER)
  return reinterpret_cast<uintptr_t>(_AddressOfReturnAddress());
#else
  uintptr_t sp = 0;
  asm volatile("mov %%rsp, %0" : "=r"(sp));
  return sp;
#endif
#elif defined(__aarch64__) || defined(_M_ARM64)
#if defined(_MSC_VER)
  return reinterpret_cast<uintptr_t>(_AddressOfReturnAddress());
#else
  uintptr_t sp = 0;
  asm volatile("mov %0, sp" : "=r"(sp));
  return sp;
#endif
#else
  return 0;
#endif
}

uintptr_t read_fp() {
#if defined(__x86_64__) || defined(_M_X64)
#if defined(_MSC_VER)
  return 0;
#else
  uintptr_t fp = 0;
  asm volatile("mov %%rbp, %0" : "=r"(fp));
  return fp;
#endif
#elif defined(__aarch64__) || defined(_M_ARM64)
#if defined(_MSC_VER)
  return 0;
#else
  uintptr_t fp = 0;
  asm volatile("mov %0, x29" : "=r"(fp));
  return fp;
#endif
#else
  return 0;
#endif
}

bool sp_alignment_ok(uintptr_t sp) {
  if (sp == 0) {
    return true;
  }
  uint64_t mod = sp % 16;
  return mod == 0 || mod == 8;
}

INSTRAWARE_NOINLINE bool check_frame_chain_inner(size_t depth, size_t max_depth, void* expected_prev, bool* checked) {
#if defined(__GNUC__) || defined(__clang__)
  uintptr_t fp_value = read_fp();
  if (fp_value == 0) {
    if (checked) {
      *checked = false;
    }
    return true;
  }
  void* fp = reinterpret_cast<void*>(fp_value);
  if (expected_prev) {
    void** slot = reinterpret_cast<void**>(fp);
    if (!slot || slot[0] == nullptr) {
      if (checked) {
        *checked = false;
      }
      return true;
    }
    if (slot[0] != expected_prev) {
      return false;
    }
  }
  // Prevent tail recursion elimination so each depth has its own frame.
  volatile uintptr_t sink = fp_value;
  if (depth < max_depth) {
    bool ok = check_frame_chain_inner(depth + 1, max_depth, fp, checked);
    sink ^= fp_value;
    if (!ok) {
      return false;
    }
  }
  if (sink == 0xdeadbeefULL) {
    return false;
  }
  if (checked) {
    *checked = true;
  }
  return true;
#else
  (void) depth;
  (void) max_depth;
  (void) expected_prev;
  if (checked) {
    *checked = false;
  }
  return true;
#endif
}

bool check_frame_chain(size_t depth, std::string* notes, bool* checked) {
  if (checked) {
    *checked = false;
  }
#if defined(__GNUC__) || defined(__clang__)
  constexpr size_t kMaxDepth = 8;
  if (depth == 0 || depth > kMaxDepth) {
    depth = depth == 0 ? 1 : kMaxDepth;
  }
  bool ok = check_frame_chain_inner(0, depth, nullptr, checked);
  if (!ok) {
    return false;
  }
  if (!checked || !*checked) {
    if (notes) {
      if (notes->find("frame_chain_skipped") == std::string::npos) {
        *notes += "frame_chain_skipped;";
      }
    }
    return true;
  }
  if (notes) {
    if (notes->find("frame_chain_internal") == std::string::npos) {
      *notes += "frame_chain_internal;";
    }
  }
  return true;
#else
  if (notes) {
    if (notes->find("frame_chain_skipped") == std::string::npos) {
      *notes += "frame_chain_skipped;";
    }
  }
  return true;
#endif
}

INSTRAWARE_NOINLINE void fill_sentinel(volatile uint64_t* data, size_t count, uint64_t seed) {
  for (size_t i = 0; i < count; ++i) {
    data[i] = seed ^ (0x9e3779b97f4a7c15ULL + static_cast<uint64_t>(i) * 0x10001ULL);
  }
}

INSTRAWARE_NOINLINE bool verify_sentinel(volatile uint64_t* data, size_t count, uint64_t seed) {
  for (size_t i = 0; i < count; ++i) {
    uint64_t expected = seed ^ (0x9e3779b97f4a7c15ULL + static_cast<uint64_t>(i) * 0x10001ULL);
    if (data[i] != expected) {
      return false;
    }
  }
  return true;
}

INSTRAWARE_NOINLINE void probe_frame(
    int depth, int max_depth, uint64_t* sentinel_failures, uint64_t* alignment_failures
) {
  volatile uint64_t sentinel[8];
  uint64_t seed = 0x13579bdf2468ace0ULL ^ static_cast<uint64_t>(depth);
  fill_sentinel(sentinel, 8, seed);

  uintptr_t sp = read_sp();
  if (!sp_alignment_ok(sp)) {
    (*alignment_failures)++;
  }

  if (depth < max_depth) {
    probe_frame(depth + 1, max_depth, sentinel_failures, alignment_failures);
  }

  if (!verify_sentinel(sentinel, 8, seed)) {
    (*sentinel_failures)++;
  }
}

} // namespace

int main(int argc, char** argv) {
  instraware::args args = instraware::parse_args(argc, argv);
  instraware::result result;
  result.test_id = "stack";
  result.platform = instraware::platform();
  result.arch = instraware::arch();

  FILE* out = instraware::open_output(args.json_out);

  uint64_t iterations = args.iterations == 0 ? 1000 : args.iterations;
  uint64_t sentinel_failures = 0;
  uint64_t alignment_failures = 0;
  uint64_t chain_failures = 0;
  uint64_t chain_checks = 0;
  std::string notes;

  for (uint64_t i = 0; i < iterations; ++i) {
    probe_frame(0, 4, &sentinel_failures, &alignment_failures);
    bool checked = false;
    if (!check_frame_chain(4, &notes, &checked)) {
      chain_failures++;
    }
    if (checked) {
      chain_checks++;
    }
  }

  result.iterations = iterations;
  result.anomalies = sentinel_failures + alignment_failures + chain_failures;
  double ratio = iterations ? static_cast<double>(result.anomalies) / static_cast<double>(iterations) : 0.0;
  result.score = ratio > 1.0 ? 1.0 : ratio;
  result.confidence = notes.find("frame_chain_skipped") != std::string::npos ? 0.6 : 0.8;

  notes += "sentinel_failures=" + std::to_string(sentinel_failures) + ";";
  notes += "alignment_failures=" + std::to_string(alignment_failures) + ";";
  notes += "chain_failures=" + std::to_string(chain_failures) + ";";
  notes += "chain_checks=" + std::to_string(chain_checks) + ";";
  result.notes = notes;

  instraware::emit_json(result, out);
  instraware::close_output(out);
  return 0;
}
