#pragma once

#include <cstdint>

#include <QBDI.h>

namespace w1 {
namespace runtime {
class module_registry;
} // namespace runtime
namespace util {
class memory_reader;
} // namespace util

class trace_context {
public:
  trace_context(uint64_t thread_id, QBDI::VM* vm, runtime::module_registry* modules, const util::memory_reader* memory)
      : thread_id_(thread_id), vm_(vm), modules_(modules), memory_(memory) {}

  uint64_t thread_id() const { return thread_id_; }
  runtime::module_registry& modules() { return *modules_; }
  const runtime::module_registry& modules() const { return *modules_; }
  const util::memory_reader& memory() const { return *memory_; }
  QBDI::VM* vm() const { return vm_; }

private:
  uint64_t thread_id_ = 0;
  QBDI::VM* vm_ = nullptr;
  runtime::module_registry* modules_ = nullptr;
  const util::memory_reader* memory_ = nullptr;
};

} // namespace w1
