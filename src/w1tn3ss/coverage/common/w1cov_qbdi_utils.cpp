#include "w1cov_qbdi_utils.hpp"
#include <cstdarg>
#include <cstdio>
#include <string>

namespace w1::coverage {

instrumentation_vm::instrumentation_vm()
    : qbdi_vm_(std::make_unique<QBDI::VM>()), virtual_stack_memory_(nullptr), vm_initialized_(false),
      virtual_stack_allocated_(false) {
  vm_initialized_ = (qbdi_vm_ != nullptr);
}

instrumentation_vm::~instrumentation_vm() {
  if (virtual_stack_memory_) {
    QBDI::alignedFree(virtual_stack_memory_);
    virtual_stack_memory_ = nullptr;
  }
}

bool instrumentation_vm::initialize_with_stack(size_t stack_size_bytes) {
  if (!vm_initialized_ || virtual_stack_allocated_) {
    return false; // Already initialized or VM not ready
  }

  QBDI::GPRState* gpr_state = qbdi_vm_->getGPRState();
  if (!gpr_state) {
    return false;
  }

  bool allocation_successful = QBDI::allocateVirtualStack(gpr_state, stack_size_bytes, &virtual_stack_memory_);

  virtual_stack_allocated_ = allocation_successful && (virtual_stack_memory_ != nullptr);
  return virtual_stack_allocated_;
}

bool instrumentation_vm::register_coverage_callback(
    QBDI::InstCallback callback_function, void* user_data, QBDI::InstPosition when
) {
  if (!is_ready_for_instrumentation()) {
    return false;
  }

  uint32_t callback_id =
      qbdi_vm_->addCodeCB(when, callback_function, user_data, QBDI::CallbackPriority::PRIORITY_DEFAULT);

  return callback_id != QBDI::VMError::INVALID_EVENTID;
}

namespace modules {

std::vector<QBDI::MemoryMap> discover_executable_modules_in_process(bool exclude_system_libraries) {
  std::vector<QBDI::MemoryMap> discovered_modules;

  try {
    // Get all memory mappings for current process
    std::vector<QBDI::MemoryMap> all_process_maps = QBDI::getCurrentProcessMaps(false);

    for (const auto& memory_map : all_process_maps) {
      // Only interested in executable regions
      bool is_executable = (memory_map.permission & QBDI::PF_EXEC) != 0;
      if (!is_executable) {
        continue;
      }

      // Skip anonymous mappings without module names
      bool has_module_name = !memory_map.name.empty();
      if (!has_module_name) {
        continue;
      }

      // Apply system library filtering if requested
      bool should_exclude_this_module = exclude_system_libraries && is_system_library_module(memory_map.name);
      if (should_exclude_this_module) {
        continue;
      }

      discovered_modules.push_back(memory_map);
    }

  } catch (const std::exception&) {
    // QBDI errors or memory access issues - return empty list
    discovered_modules.clear();
  }

  return discovered_modules;
}

bool is_system_library_module(const std::string& module_path) {
  // Cross-platform system library detection patterns

  // macOS system paths
  if (module_path.find("/System/") != std::string::npos || module_path.find("/usr/lib/") != std::string::npos ||
      module_path.find("/usr/local/lib/") != std::string::npos || module_path.find("libsystem_") != std::string::npos ||
      module_path.find("libc++") != std::string::npos || module_path.find("libdyld") != std::string::npos) {
    return true;
  }

  // Linux system paths
  if (module_path.find("/lib/") != std::string::npos || module_path.find("ld-linux") != std::string::npos ||
      module_path.find("libc.so") != std::string::npos) {
    return true;
  }

  // Windows system paths
  if (module_path.find("C:\\Windows\\System32\\") != std::string::npos ||
      module_path.find("ntdll.dll") != std::string::npos || module_path.find("kernel32.dll") != std::string::npos) {
    return true;
  }

  return false;
}

std::string get_module_display_name(const std::string& full_module_path, bool use_full_path) {
  if (use_full_path) {
    return full_module_path;
  }

  // Extract just the filename from the path
  size_t last_path_separator = full_module_path.find_last_of("/\\");
  if (last_path_separator != std::string::npos) {
    return full_module_path.substr(last_path_separator + 1);
  }

  // Path has no separators, return as-is
  return full_module_path;
}

} // namespace modules

namespace output {

void injection_safe_printf(const char* format, ...) {
  // Use C-style printf to avoid C++ stream complexities in injection
  va_list args;
  va_start(args, format);
  vprintf(format, args);
  va_end(args);
  fflush(stdout); // Ensure output appears immediately
}

} // namespace output

} // namespace w1::coverage