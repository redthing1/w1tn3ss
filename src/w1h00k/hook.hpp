#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>

namespace w1::h00k {

enum class hook_technique {
  inline_trampoline = 0,
  interpose,
  plt_got,
  iat,
  table_swap,
  count
};

enum class hook_kind {
  replace,
  instrument
};

using hook_technique_mask = uint32_t;

constexpr hook_technique_mask technique_mask(hook_technique technique) {
  if (technique == hook_technique::count) {
    return 0;
  }
  return static_cast<hook_technique_mask>(1u << static_cast<uint32_t>(technique));
}

constexpr bool technique_allowed(hook_technique_mask mask, hook_technique technique) {
  return (mask & technique_mask(technique)) != 0;
}

enum class hook_selection {
  strict,
  allow_fallback
};

enum class hook_target_kind {
  address,
  symbol,
  import_slot,
  table_slot
};

enum class hook_call_abi {
  native,
  sysv,
  win64,
  aapcs64
};

enum class hook_error {
  ok,
  unsupported,
  invalid_target,
  relocation_failed,
  near_alloc_failed,
  patch_failed,
  already_hooked,
  not_found,
  access_denied
};

struct hook_target {
  hook_target_kind kind = hook_target_kind::address;
  void* address = nullptr;
  const char* symbol = nullptr;
  const char* module = nullptr;
  const char* import_module = nullptr;
  void** slot = nullptr;
  void** table = nullptr;
  size_t index = 0;
};

struct hook_arg_handle;

struct hook_info {
  void* original_target = nullptr;
  void* target = nullptr;
  void* trampoline = nullptr;
  void* replacement = nullptr;
  void* user_data = nullptr;
  hook_arg_handle* args = nullptr;
};

using prehook_fn = void (*)(hook_info*);

struct hook_request {
  hook_target target{};
  void* replacement = nullptr;
  hook_technique preferred = hook_technique::inline_trampoline;
  hook_technique_mask allowed = 0;
  hook_selection selection = hook_selection::strict;
  hook_kind kind = hook_kind::replace;
  hook_call_abi call_abi = hook_call_abi::native;
  prehook_fn prehook = nullptr;
  void* user_data = nullptr;
};

struct hook_handle {
  uintptr_t id = 0;
};

struct hook_error_info {
  hook_error code = hook_error::unsupported;
  int os_error = 0;
  const char* detail = nullptr;

  constexpr bool ok() const { return code == hook_error::ok; }
};

struct hook_result {
  hook_handle handle{};
  hook_error_info error{};
};

class hook_transaction {
public:
  hook_transaction();
  ~hook_transaction();
  hook_transaction(hook_transaction&&) noexcept;
  hook_transaction& operator=(hook_transaction&&) noexcept;
  hook_transaction(const hook_transaction&) = delete;
  hook_transaction& operator=(const hook_transaction&) = delete;

  hook_result attach(const hook_request& request, void** original);
  hook_error detach(hook_handle handle);
  hook_error commit();

private:
  struct impl;
  std::unique_ptr<impl> impl_{};
};

hook_result attach(const hook_request& request, void** original);
hook_error detach(hook_handle handle);
bool supports(const hook_request& request);

void* arg_get_int_reg_addr(const hook_arg_handle* args, int pos);
void* arg_get_flt_reg_addr(const hook_arg_handle* args, int pos);
void* arg_get_stack_addr(const hook_arg_handle* args, int pos);

using interpose_pair = std::pair<const char*, void*>;
void register_interpose(const interpose_pair* pairs, size_t count);

} // namespace w1::h00k
