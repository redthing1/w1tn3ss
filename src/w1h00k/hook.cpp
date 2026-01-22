#include "w1h00k/hook.hpp"

#include "w1h00k/core/hook_args.hpp"
#include "w1h00k/core/hook_manager.hpp"
#include "w1h00k/core/hook_transaction.hpp"

namespace w1::h00k {
namespace {

struct abi_layout {
  size_t int_reg_count = 0;
  size_t flt_reg_count = 0;
  size_t int_stride = 0;
  size_t flt_stride = 0;
  size_t stack_offset = 0;
  size_t stack_slot = 0;
};

hook_call_abi resolve_native_abi() {
#if defined(_WIN32)
#if defined(_M_X64) || defined(__x86_64__)
  return hook_call_abi::win64;
#elif defined(_M_IX86) || defined(__i386__)
  return hook_call_abi::win32_cdecl;
#elif defined(_M_ARM64) || defined(__aarch64__)
  return hook_call_abi::aapcs64;
#else
  return hook_call_abi::sysv;
#endif
#else
#if defined(__aarch64__)
  return hook_call_abi::aapcs64;
#else
  return hook_call_abi::sysv;
#endif
#endif
}

bool layout_for(hook_call_abi abi, abi_layout& out) {
  const size_t ptr_size = sizeof(void*);
  out.int_stride = ptr_size;
  out.flt_stride = 16;
  out.stack_slot = ptr_size;

  switch (abi) {
    case hook_call_abi::sysv:
      if (ptr_size == 4) {
        out.int_reg_count = 0;
        out.flt_reg_count = 0;
        out.stack_offset = 4;
        out.stack_slot = 4;
      } else {
        out.int_reg_count = 6;
        out.flt_reg_count = 8;
        out.stack_offset = 8;
      }
      return true;
    case hook_call_abi::win64:
      if (ptr_size != 8) {
        return false;
      }
      out.int_reg_count = 4;
      out.flt_reg_count = 4;
      out.stack_offset = 8 + 32;
      return true;
    case hook_call_abi::win64_vectorcall:
      if (ptr_size != 8) {
        return false;
      }
      out.int_reg_count = 4;
      out.flt_reg_count = 6;
      out.stack_offset = 8 + 32;
      return true;
    case hook_call_abi::win32_cdecl:
    case hook_call_abi::win32_stdcall:
      if (ptr_size != 4) {
        return false;
      }
      out.int_reg_count = 0;
      out.flt_reg_count = 0;
      out.stack_offset = 4;
      out.stack_slot = 4;
      return true;
    case hook_call_abi::win32_fastcall:
      if (ptr_size != 4) {
        return false;
      }
      out.int_reg_count = 2;
      out.flt_reg_count = 0;
      out.stack_offset = 4;
      out.stack_slot = 4;
      return true;
    case hook_call_abi::win32_thiscall:
      if (ptr_size != 4) {
        return false;
      }
      out.int_reg_count = 1;
      out.flt_reg_count = 0;
      out.stack_offset = 4;
      out.stack_slot = 4;
      return true;
    case hook_call_abi::aapcs64:
      if (ptr_size != 8) {
        return false;
      }
      out.int_reg_count = 8;
      out.flt_reg_count = 8;
      out.stack_offset = 0;
      return true;
    case hook_call_abi::native:
      return layout_for(resolve_native_abi(), out);
    default:
      return false;
  }
}

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
  if (!args || pos < 0 || !args->int_regs) {
    return nullptr;
  }

  abi_layout layout{};
  if (!layout_for(args->abi, layout)) {
    return nullptr;
  }

  if (static_cast<size_t>(pos) >= layout.int_reg_count) {
    return nullptr;
  }

  auto* base = static_cast<uint8_t*>(const_cast<void*>(args->int_regs));
  return base + (static_cast<size_t>(pos) * layout.int_stride);
}

void* arg_get_flt_reg_addr(const hook_arg_handle* args, int pos) {
  if (!args || pos < 0 || !args->flt_regs) {
    return nullptr;
  }

  abi_layout layout{};
  if (!layout_for(args->abi, layout)) {
    return nullptr;
  }

  if (static_cast<size_t>(pos) >= layout.flt_reg_count) {
    return nullptr;
  }

  auto* base = static_cast<uint8_t*>(const_cast<void*>(args->flt_regs));
  return base + (static_cast<size_t>(pos) * layout.flt_stride);
}

void* arg_get_stack_addr(const hook_arg_handle* args, int pos) {
  if (!args || pos < 0 || !args->stack) {
    return nullptr;
  }

  abi_layout layout{};
  if (!layout_for(args->abi, layout)) {
    return nullptr;
  }

  auto* base = static_cast<uint8_t*>(const_cast<void*>(args->stack));
  return base + layout.stack_offset + (static_cast<size_t>(pos) * layout.stack_slot);
}

void register_interpose(const interpose_pair* pairs, size_t count) {
  if (!pairs || count == 0) {
    return;
  }
  for (size_t i = 0; i < count; ++i) {
    const auto& entry = pairs[i];
    if (!entry.first || !entry.second) {
      continue;
    }
    hook_request request{};
    request.target.kind = hook_target_kind::symbol;
    request.target.symbol = entry.first;
    request.replacement = entry.second;
    request.preferred = hook_technique::interpose;
    request.allowed = technique_mask(hook_technique::interpose);
    request.selection = hook_selection::strict;
    (void)attach(request, nullptr);
  }
}

} // namespace w1::h00k
