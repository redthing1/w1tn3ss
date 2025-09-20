#include "placeholder.hpp"
#include <sstream>
#include <stdexcept>

namespace w1::abi::conventions {

placeholder_calling_convention::placeholder_calling_convention(
    calling_convention_id id, std::string name, architecture arch, std::string description, stack_cleanup cleanup
)
    : id_(id), name_(std::move(name)), arch_(arch), description_(std::move(description)), cleanup_(cleanup) {}

calling_convention_id placeholder_calling_convention::get_id() const { return id_; }

std::string placeholder_calling_convention::get_name() const { return name_; }

architecture placeholder_calling_convention::get_architecture() const { return arch_; }

std::string placeholder_calling_convention::get_description() const { return description_; }

std::vector<uint64_t> placeholder_calling_convention::extract_integer_args(const extraction_context&, size_t) const {
  throw_not_supported("extract_integer_args");
}

std::vector<calling_convention_base::typed_arg> placeholder_calling_convention::extract_typed_args(
    const extraction_context&, const std::vector<arg_type>&
) const {
  throw_not_supported("extract_typed_args");
}

uint64_t placeholder_calling_convention::get_integer_return(const QBDI::GPRState*) const {
  throw_not_supported("get_integer_return");
}

double placeholder_calling_convention::get_float_return(const QBDI::FPRState*) const {
  throw_not_supported("get_float_return");
}

calling_convention_base::typed_arg placeholder_calling_convention::get_typed_return(
    const QBDI::GPRState*, const QBDI::FPRState*, arg_type
) const {
  throw_not_supported("get_typed_return");
}

uint64_t placeholder_calling_convention::get_stack_pointer(const QBDI::GPRState*) const {
  throw_not_supported("get_stack_pointer");
}

uint64_t placeholder_calling_convention::get_frame_pointer(const QBDI::GPRState*) const {
  throw_not_supported("get_frame_pointer");
}

size_t placeholder_calling_convention::get_stack_alignment() const { return 0; }

size_t placeholder_calling_convention::get_red_zone_size() const { return 0; }

size_t placeholder_calling_convention::get_shadow_space_size() const { return 0; }

uint64_t placeholder_calling_convention::get_return_address_location(const QBDI::GPRState*) const {
  throw_not_supported("get_return_address_location");
}

bool placeholder_calling_convention::supports_varargs() const { return false; }

std::optional<calling_convention_base::variadic_info> placeholder_calling_convention::get_variadic_info(
    const extraction_context&, size_t
) const {
  return std::nullopt;
}

calling_convention_base::register_info placeholder_calling_convention::get_register_info() const { return {}; }

bool placeholder_calling_convention::is_native_for_current_platform() const { return false; }

calling_convention_base::stack_cleanup placeholder_calling_convention::get_stack_cleanup() const { return cleanup_; }

std::vector<double> placeholder_calling_convention::extract_float_args(const extraction_context&, size_t) const {
  throw_not_supported("extract_float_args");
}

void placeholder_calling_convention::set_integer_args(
    QBDI::GPRState*, const std::vector<uint64_t>&, std::function<void(uint64_t, uint64_t)>
) const {
  throw_not_supported("set_integer_args");
}

void placeholder_calling_convention::set_typed_args(
    QBDI::GPRState*, QBDI::FPRState*, const std::vector<typed_arg>&, std::function<void(uint64_t, uint64_t)>
) const {
  throw_not_supported("set_typed_args");
}

void placeholder_calling_convention::set_integer_return(QBDI::GPRState*, uint64_t) const {
  throw_not_supported("set_integer_return");
}

void placeholder_calling_convention::set_float_return(QBDI::FPRState*, double) const {
  throw_not_supported("set_float_return");
}

[[noreturn]] void placeholder_calling_convention::throw_not_supported(const char* what) const {
  std::ostringstream oss;
  oss << "calling convention '" << name_ << "' does not support operation '" << what << "'";
  throw std::runtime_error(oss.str());
}

unknown_calling_convention::unknown_calling_convention()
    : placeholder_calling_convention(
          calling_convention_id::UNKNOWN, "unknown calling convention", architecture::UNKNOWN,
          "Placeholder for unresolved calling conventions"
      ) {}

custom_calling_convention::custom_calling_convention()
    : placeholder_calling_convention(
          calling_convention_id::CUSTOM, "custom calling convention", architecture::UNKNOWN,
          "User-defined calling convention placeholder"
      ) {}

} // namespace w1::abi::conventions
