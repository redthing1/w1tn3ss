#include "w1h00k/hook.hpp"

#include "w1h00k/core/hook_manager.hpp"

namespace w1::h00k {
namespace {

bool is_valid_target(const hook_target& target) {
  return target.address != nullptr || target.symbol != nullptr;
}

core::hook_manager& global_manager() {
  static core::hook_manager manager{};
  return manager;
}

} // namespace

hook_result hook_transaction::attach(const hook_request& request, void** original) {
  if (!is_valid_target(request.target)) {
    if (original) {
      *original = nullptr;
    }
    return {{}, hook_error::invalid_target};
  }
  if (original) {
    *original = nullptr;
  }
  return {{}, hook_error::unsupported};
}

hook_error hook_transaction::detach(hook_handle handle) {
  (void)handle;
  return hook_error::unsupported;
}

hook_error hook_transaction::commit() {
  return hook_error::unsupported;
}

hook_result attach(const hook_request& request, void** original) {
  if (!is_valid_target(request.target)) {
    if (original) {
      *original = nullptr;
    }
    return {{}, hook_error::invalid_target};
  }
  return global_manager().attach(request, original);
}

hook_error detach(hook_handle handle) {
  return global_manager().detach(handle);
}

bool supports(const hook_request& request) {
  if (!is_valid_target(request.target)) {
    return false;
  }
  return global_manager().supports(request);
}

void* arg_get_int_reg_addr(const hook_arg_handle* args, int pos) {
  (void)args;
  (void)pos;
  return nullptr;
}

void* arg_get_flt_reg_addr(const hook_arg_handle* args, int pos) {
  (void)args;
  (void)pos;
  return nullptr;
}

void* arg_get_stack_addr(const hook_arg_handle* args, int pos) {
  (void)args;
  (void)pos;
  return nullptr;
}

void register_interpose(const interpose_pair* pairs, size_t count) {
  (void)pairs;
  (void)count;
}

} // namespace w1::h00k
