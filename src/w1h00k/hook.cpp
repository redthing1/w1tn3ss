#include "w1h00k/hook.hpp"

#include "w1h00k/core/hook_manager.hpp"
#include "w1h00k/core/hook_transaction.hpp"

namespace w1::h00k {
namespace {

core::hook_manager& global_manager() {
  static core::hook_manager manager{};
  return manager;
}

} // namespace

struct hook_transaction::impl {
  core::hook_transaction transaction;

  explicit impl(core::hook_manager& manager) : transaction(manager) {}
};

hook_transaction::hook_transaction() : impl_(std::make_unique<impl>(global_manager())) {}

hook_transaction::~hook_transaction() = default;

hook_transaction::hook_transaction(hook_transaction&&) noexcept = default;
hook_transaction& hook_transaction::operator=(hook_transaction&&) noexcept = default;

hook_result hook_transaction::attach(const hook_request& request, void** original) {
  return impl_->transaction.attach(request, original);
}

hook_error hook_transaction::detach(hook_handle handle) {
  return impl_->transaction.detach(handle);
}

hook_error hook_transaction::commit() {
  return impl_->transaction.commit();
}

hook_result attach(const hook_request& request, void** original) {
  return global_manager().attach(request, original);
}

hook_error detach(hook_handle handle) {
  return global_manager().detach(handle);
}

bool supports(const hook_request& request) {
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
