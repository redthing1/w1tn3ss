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
  bool ok = VirtualProtect(buffer->data, buffer->size, PAGE_EXECUTE_READ, &old_protect) != 0;
  FlushInstructionCache(GetCurrentProcess(), buffer->data, buffer->size);
  return ok;
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

bool write_return_constant(exec_buffer* buffer, uint32_t value) {
  if (!buffer || !buffer->data) {
    return false;
  }
#if defined(__x86_64__) || defined(_M_X64)
  if (buffer->size < 6) {
    return false;
  }
  buffer->data[0] = 0xB8;
  std::memcpy(buffer->data + 1, &value, sizeof(uint32_t));
  buffer->data[5] = 0xC3;
  return true;
#elif defined(__aarch64__) || defined(_M_ARM64)
  if (buffer->size < 8) {
    return false;
  }
  uint32_t mov = 0x52800000 | ((value & 0xFFFFU) << 5);
  buffer->data[0] = static_cast<uint8_t>(mov & 0xFF);
  buffer->data[1] = static_cast<uint8_t>((mov >> 8) & 0xFF);
  buffer->data[2] = static_cast<uint8_t>((mov >> 16) & 0xFF);
  buffer->data[3] = static_cast<uint8_t>((mov >> 24) & 0xFF);
  buffer->data[4] = 0xC0;
  buffer->data[5] = 0x03;
  buffer->data[6] = 0x5F;
  buffer->data[7] = 0xD6;
  return true;
#else
  return false;
#endif
}

} // namespace

int main(int argc, char** argv) {
  instraware::args args = instraware::parse_args(argc, argv);
  instraware::result result;
  result.test_id = "smc";
  result.platform = instraware::platform();
  result.arch = instraware::arch();

  FILE* out = instraware::open_output(args.json_out);

  exec_buffer buffer;
  if (!alloc_exec_buffer(&buffer, 64)) {
    result.iterations = 0;
    result.score = 0.0;
    result.confidence = 0.3;
    result.anomalies = 0;
    result.notes = "jit_allocation_failed";
    instraware::emit_json(result, out);
    instraware::close_output(out);
    return 0;
  }

  using smc_fn_t = uint32_t (*)();
  auto fn = reinterpret_cast<smc_fn_t>(buffer.data);

  uint64_t iterations = args.iterations == 0 ? 100 : args.iterations;
  uint64_t anomalies = 0;

  for (uint64_t i = 0; i < iterations; ++i) {
    if (!make_buffer_writable(&buffer) || !write_return_constant(&buffer, 1) || !make_buffer_executable(&buffer)) {
      anomalies++;
      continue;
    }
    uint32_t v1 = fn();

    if (!make_buffer_writable(&buffer) || !write_return_constant(&buffer, 2) || !make_buffer_executable(&buffer)) {
      anomalies++;
      continue;
    }
    uint32_t v2 = fn();

    if (v1 != 1 || v2 != 2) {
      anomalies++;
    }
  }

  result.iterations = iterations;
  result.anomalies = anomalies;
  result.score = iterations ? static_cast<double>(anomalies) / static_cast<double>(iterations) : 0.0;
  result.confidence = 0.7;
  result.notes = "smc_checked";

  instraware::emit_json(result, out);
  instraware::close_output(out);
  free_exec_buffer(&buffer);
  return 0;
}
