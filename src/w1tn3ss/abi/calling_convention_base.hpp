#pragma once

#include <QBDI.h>
#include <memory>
#include <vector>
#include <optional>
#include <string>
#include <functional>
#include <cstdint>

namespace w1::abi {

// calling convention identifier
enum class calling_convention_id {
  UNKNOWN,
  // x86-64 conventions
  X86_64_SYSTEM_V,  // linux/macos x64
  X86_64_MICROSOFT, // windows x64
  // x86 conventions
  X86_CDECL,      // c calling convention
  X86_STDCALL,    // standard call (win32 api)
  X86_FASTCALL,   // fast call (register-based)
  X86_THISCALL,   // c++ member functions
  X86_VECTORCALL, // simd optimized
  // arm conventions
  AARCH64_AAPCS,   // arm 64-bit standard
  AARCH64_WINDOWS, // windows arm64
  ARM32_AAPCS,     // arm 32-bit
  // special
  CUSTOM // user-defined
};

// architecture type
enum class architecture { X86, X86_64, ARM32, AARCH64 };

// abstract base class for all calling conventions
class calling_convention_base {
public:
  virtual ~calling_convention_base() = default;

  // metadata
  virtual calling_convention_id get_id() const = 0;
  virtual std::string get_name() const = 0;
  virtual architecture get_architecture() const = 0;
  virtual std::string get_description() const = 0;

  // extraction context with all necessary data
  struct extraction_context {
    const QBDI::GPRState* gpr;
    const QBDI::FPRState* fpr;
    std::function<uint64_t(uint64_t addr)> read_stack; // safe stack reading function
  };

  // extract integer/pointer arguments
  virtual std::vector<uint64_t> extract_integer_args(const extraction_context& ctx, size_t count) const = 0;

  // argument type classification
  enum class arg_type { INTEGER, POINTER, FLOAT, DOUBLE, SIMD, STRUCT_BY_VALUE, STRUCT_BY_REF };

  // typed argument with value and metadata
  struct typed_arg {
    arg_type type;
    union {
      uint64_t integer;
      float f32;
      double f64;
      uint8_t simd[16];
      struct {
        uint64_t data[4]; // for small structs
        size_t size;
      } struct_data;
    } value;
    bool from_stack = false;
    size_t stack_offset = 0;
  };

  // extract typed arguments with type awareness
  virtual std::vector<typed_arg> extract_typed_args(
      const extraction_context& ctx, const std::vector<arg_type>& types
  ) const = 0;

  // return value extraction
  virtual uint64_t get_integer_return(const QBDI::GPRState* gpr) const = 0;
  virtual double get_float_return(const QBDI::FPRState* fpr) const = 0;
  virtual typed_arg get_typed_return(const QBDI::GPRState* gpr, const QBDI::FPRState* fpr, arg_type type) const = 0;

  // stack management
  virtual uint64_t get_stack_pointer(const QBDI::GPRState* gpr) const = 0;
  virtual uint64_t get_frame_pointer(const QBDI::GPRState* gpr) const = 0;
  virtual size_t get_stack_alignment() const = 0;
  virtual size_t get_red_zone_size() const { return 0; }

  // shadow space (windows x64 specific, but can be generalized)
  virtual size_t get_shadow_space_size() const { return 0; }

  // return address location
  virtual uint64_t get_return_address_location(const QBDI::GPRState* gpr) const = 0;

  // variadic function support
  struct variadic_info {
    size_t fixed_args;
    size_t gp_offset; // for system v
    size_t fp_offset;
    uint64_t overflow_arg_area;
    uint64_t reg_save_area;
  };

  virtual bool supports_varargs() const = 0;
  virtual std::optional<variadic_info> get_variadic_info(
      const extraction_context& ctx, size_t fixed_arg_count
  ) const = 0;

  // register preservation info
  struct register_info {
    std::vector<std::string> callee_saved_gpr;
    std::vector<std::string> caller_saved_gpr;
    std::vector<std::string> callee_saved_fpr;
    std::vector<std::string> caller_saved_fpr;
    std::string return_register;
    std::vector<std::string> argument_registers;
  };

  virtual register_info get_register_info() const = 0;

  // helper to check if convention matches current platform
  virtual bool is_native_for_current_platform() const = 0;

  // stack cleanup info
  enum class stack_cleanup {
    CALLER, // caller cleans up (cdecl)
    CALLEE, // callee cleans up (stdcall)
    HYBRID  // depends on function (fastcall with varargs)
  };

  virtual stack_cleanup get_stack_cleanup() const = 0;

  // helper for floating point arguments
  virtual std::vector<double> extract_float_args(const extraction_context& ctx, size_t count) const = 0;
};

// shared pointer type for convenience
using calling_convention_ptr = std::shared_ptr<calling_convention_base>;

// helper to convert enum to string
inline std::string to_string(calling_convention_id id) {
  switch (id) {
  case calling_convention_id::UNKNOWN:
    return "unknown";
  case calling_convention_id::X86_64_SYSTEM_V:
    return "x86_64_system_v";
  case calling_convention_id::X86_64_MICROSOFT:
    return "x86_64_microsoft";
  case calling_convention_id::X86_CDECL:
    return "x86_cdecl";
  case calling_convention_id::X86_STDCALL:
    return "x86_stdcall";
  case calling_convention_id::X86_FASTCALL:
    return "x86_fastcall";
  case calling_convention_id::X86_THISCALL:
    return "x86_thiscall";
  case calling_convention_id::X86_VECTORCALL:
    return "x86_vectorcall";
  case calling_convention_id::AARCH64_AAPCS:
    return "aarch64_aapcs";
  case calling_convention_id::AARCH64_WINDOWS:
    return "aarch64_windows";
  case calling_convention_id::ARM32_AAPCS:
    return "arm32_aapcs";
  case calling_convention_id::CUSTOM:
    return "custom";
  default:
    return "invalid";
  }
}

inline std::string to_string(architecture arch) {
  switch (arch) {
  case architecture::X86:
    return "x86";
  case architecture::X86_64:
    return "x86_64";
  case architecture::ARM32:
    return "arm32";
  case architecture::AARCH64:
    return "aarch64";
  default:
    return "unknown";
  }
}

} // namespace w1::abi