#pragma once

#include <QBDI.h>
#include <memory>
#include <string>
#include <vector>

namespace w1::coverage {

/// RAII wrapper for QBDI VM with instrumentation setup
class instrumentation_vm {
public:
  static constexpr size_t DEFAULT_STACK_SIZE = 0x100000; // 1MB

  instrumentation_vm();
  ~instrumentation_vm();

  // Non-copyable, non-movable for safety
  instrumentation_vm(const instrumentation_vm&) = delete;
  instrumentation_vm& operator=(const instrumentation_vm&) = delete;
  instrumentation_vm(instrumentation_vm&&) = delete;
  instrumentation_vm& operator=(instrumentation_vm&&) = delete;

  /// Initialize VM with virtual stack allocation
  bool initialize_with_stack(size_t stack_size_bytes = DEFAULT_STACK_SIZE);

  /// Register callback for instruction coverage collection
  bool register_coverage_callback(
      QBDI::InstCallback callback_function, void* user_data = nullptr,
      QBDI::InstPosition when = QBDI::InstPosition::PREINST
  );

  /// Access underlying QBDI VM (nullptr if not initialized)
  QBDI::VM* get_qbdi_vm() const { return qbdi_vm_.get(); }

  /// Check if VM is ready for instrumentation
  bool is_ready_for_instrumentation() const { return vm_initialized_ && virtual_stack_allocated_; }

private:
  std::unique_ptr<QBDI::VM> qbdi_vm_;
  uint8_t* virtual_stack_memory_;
  bool vm_initialized_;
  bool virtual_stack_allocated_;
};

/// Module discovery and filtering utilities
namespace modules {

/// Find all executable modules in the current process
std::vector<QBDI::MemoryMap> discover_executable_modules_in_process(bool exclude_system_libraries = true);

/// Check if module path indicates a system/standard library
bool is_system_library_module(const std::string& module_path);

/// Get display name for module (full path or basename)
std::string get_module_display_name(const std::string& full_module_path, bool use_full_path = false);

} // namespace modules

/// Injection-safe output utilities
namespace output {

/// Printf that works safely in injection contexts
void injection_safe_printf(const char* format, ...);

} // namespace output

} // namespace w1::coverage