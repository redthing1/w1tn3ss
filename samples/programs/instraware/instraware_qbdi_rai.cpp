#include "instraware_common.hpp"

#include <cstdint>
#include <cstring>
#include <string>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <pthread.h>
#include <sys/mman.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#if defined(__APPLE__) && defined(__aarch64__)
#include <ptrauth.h>
#endif

#if !defined(_WIN32)
#ifndef MAP_ANON
#define MAP_ANON MAP_ANONYMOUS
#endif
#endif

namespace {

struct exec_buffer {
  uint8_t* data = nullptr;
  size_t size = 0;
};

bool alloc_exec_buffer(exec_buffer* buffer, size_t size) {
  if (!buffer || size == 0) {
    return false;
  }
#if defined(_WIN32)
  buffer->data = static_cast<uint8_t*>(VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
  buffer->size = buffer->data ? size : 0;
  return buffer->data != nullptr;
#else
  int flags = MAP_PRIVATE | MAP_ANON;
  int prot = PROT_READ | PROT_WRITE;
#if defined(__APPLE__) && defined(__aarch64__)
  flags |= MAP_JIT;
  prot |= PROT_EXEC;
#endif
  void* ptr = mmap(nullptr, size, prot, flags, -1, 0);
  if (ptr == MAP_FAILED) {
    return false;
  }
  buffer->data = static_cast<uint8_t*>(ptr);
  buffer->size = size;
  return true;
#endif
}

bool make_buffer_writable(exec_buffer* buffer) {
  if (!buffer || !buffer->data) {
    return false;
  }
#if defined(_WIN32)
  DWORD old_protect = 0;
  return VirtualProtect(buffer->data, buffer->size, PAGE_READWRITE, &old_protect) != 0;
#elif defined(__APPLE__) && defined(__aarch64__)
  pthread_jit_write_protect_np(0);
  return true;
#else
  return mprotect(buffer->data, buffer->size, PROT_READ | PROT_WRITE) == 0;
#endif
}

bool make_buffer_executable(exec_buffer* buffer) {
  if (!buffer || !buffer->data) {
    return false;
  }
#if defined(_WIN32)
  DWORD old_protect = 0;
  return VirtualProtect(buffer->data, buffer->size, PAGE_EXECUTE_READ, &old_protect) != 0;
#elif defined(__APPLE__) && defined(__aarch64__)
  pthread_jit_write_protect_np(1);
  __builtin___clear_cache(reinterpret_cast<char*>(buffer->data), reinterpret_cast<char*>(buffer->data + buffer->size));
  return true;
#else
  bool ok = mprotect(buffer->data, buffer->size, PROT_READ | PROT_EXEC) == 0;
  __builtin___clear_cache(reinterpret_cast<char*>(buffer->data), reinterpret_cast<char*>(buffer->data + buffer->size));
  return ok;
#endif
}

void free_exec_buffer(exec_buffer* buffer) {
  if (!buffer || !buffer->data) {
    return;
  }
#if defined(_WIN32)
  VirtualFree(buffer->data, 0, MEM_RELEASE);
#else
  munmap(buffer->data, buffer->size);
#endif
  buffer->data = nullptr;
  buffer->size = 0;
}

uintptr_t strip_pac(uintptr_t value) {
#if defined(__APPLE__) && defined(__aarch64__) && defined(__has_feature)
#if __has_feature(ptrauth_calls)
  return reinterpret_cast<uintptr_t>(ptrauth_strip(reinterpret_cast<void*>(value), ptrauth_key_return_address));
#endif
#endif
  return value;
}

bool build_rai_stub(exec_buffer* buffer, std::string* notes) {
  if (!buffer || !buffer->data) {
    return false;
  }
  if (!make_buffer_writable(buffer)) {
    if (notes) {
      *notes = "jit_write_protect_failed";
    }
    return false;
  }

#if defined(__x86_64__) || defined(_M_X64)
#if defined(_WIN32)
  const uint8_t code[] = {0x48, 0x8B, 0x04, 0x24, 0x48, 0x89, 0x01, 0xC3};
#else
  const uint8_t code[] = {0x48, 0x8B, 0x04, 0x24, 0x48, 0x89, 0x07, 0xC3};
#endif
  if (buffer->size < sizeof(code)) {
    return false;
  }
  std::memcpy(buffer->data, code, sizeof(code));
#elif defined(__aarch64__) || defined(_M_ARM64)
  const uint8_t code[] = {0x1E, 0x00, 0x00, 0xF9, 0xC0, 0x03, 0x5F, 0xD6};
  if (buffer->size < sizeof(code)) {
    return false;
  }
  std::memcpy(buffer->data, code, sizeof(code));
#else
  if (notes) {
    *notes = "unsupported_arch";
  }
  return false;
#endif

  return make_buffer_executable(buffer);
}

} // namespace

int main(int argc, char** argv) {
  instraware::args args = instraware::parse_args(argc, argv);
  instraware::result result;
  result.test_id = "rai";
  result.platform = instraware::platform();
  result.arch = instraware::arch();

  FILE* out = instraware::open_output(args.json_out);

#if defined(_MSC_VER)
  result.iterations = 0;
  result.score = 0.0;
  result.confidence = 0.3;
  result.anomalies = 0;
  result.notes = "rai_subtest_skipped: no portable callsite marker on msvc";
  instraware::emit_json(result, out);
  instraware::close_output(out);
  return 0;
#endif

  exec_buffer buffer;
  std::string notes;
  if (!alloc_exec_buffer(&buffer, 64) || !build_rai_stub(&buffer, &notes)) {
    result.iterations = 0;
    result.score = 0.0;
    result.confidence = 0.3;
    result.anomalies = 0;
    result.notes = notes.empty() ? "jit_allocation_failed" : notes;
    instraware::emit_json(result, out);
    instraware::close_output(out);
    free_exec_buffer(&buffer);
    return 0;
  }

  using rai_fn_t = void (*)(uintptr_t*);
  auto fn = reinterpret_cast<rai_fn_t>(buffer.data);

  uint64_t iterations = args.iterations == 0 ? 1000 : args.iterations;
  uint64_t mismatches = 0;
  bool have_label = true;

  for (uint64_t i = 0; i < iterations; ++i) {
    uintptr_t observed = 0;
    uintptr_t expected = 0;
#if defined(__GNUC__) || defined(__clang__)
    expected = reinterpret_cast<uintptr_t>(&&after_call);
#else
    have_label = false;
#endif
    fn(&observed);
after_call:
    observed = strip_pac(observed);
    expected = strip_pac(expected);
    if (have_label && observed != expected) {
      mismatches++;
    }
  }

  result.iterations = have_label ? iterations : 0;
  result.anomalies = mismatches;
  result.score = have_label && iterations ? static_cast<double>(mismatches) / static_cast<double>(iterations) : 0.0;
  result.confidence = have_label ? 0.8 : 0.3;
  result.notes = have_label ? "rai_checked" : "rai_subtest_skipped: no label support";

  instraware::emit_json(result, out);
  instraware::close_output(out);
  free_exec_buffer(&buffer);
  return 0;
}
