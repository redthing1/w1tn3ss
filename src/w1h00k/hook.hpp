#pragma once

#include <cstddef>
#include <cstdint>
#include <utility>

namespace w1::h00k {

enum class hook_technique {
  inline_trampoline,
  interpose,
  plt_got,
  iat,
  table_swap
};

enum class hook_kind {
  replace,
  instrument
};

using hook_technique_mask = uint32_t;

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
  void* address = nullptr;
  const char* symbol = nullptr;
  const char* module = nullptr;
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
  hook_technique_mask allowed = 0;
  hook_kind kind = hook_kind::replace;
  prehook_fn prehook = nullptr;
  void* user_data = nullptr;
};

struct hook_handle {
  uintptr_t id = 0;
};

struct hook_result {
  hook_handle handle{};
  hook_error error = hook_error::unsupported;
};

class hook_transaction {
public:
  hook_result attach(const hook_request& request, void** original);
  hook_error detach(hook_handle handle);
  hook_error commit();
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
