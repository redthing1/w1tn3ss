#pragma once

#include "w1h00k/hook.hpp"

namespace w1::monitor::backend::hook_helpers {

inline bool attach_interpose_symbol(const char* symbol,
                                    void* replacement,
                                    w1::h00k::hook_handle& handle_out,
                                    void*& original_out) {
  w1::h00k::hook_request request{};
  request.target.kind = w1::h00k::hook_target_kind::symbol;
  request.target.symbol = symbol;
  request.replacement = replacement;
  request.preferred = w1::h00k::hook_technique::interpose;
  request.allowed = w1::h00k::technique_mask(w1::h00k::hook_technique::interpose);
  request.selection = w1::h00k::hook_selection::strict;

  void* original = nullptr;
  auto result = w1::h00k::attach(request, &original);
  if (!result.error.ok()) {
    return false;
  }

  handle_out = result.handle;
  original_out = original;
  return true;
}

template <typename Fn>
inline bool attach_interpose_symbol(const char* symbol,
                                    void* replacement,
                                    w1::h00k::hook_handle& handle_out,
                                    Fn& original_out) {
  void* original = nullptr;
  if (!attach_interpose_symbol(symbol, replacement, handle_out, original)) {
    return false;
  }
  original_out = reinterpret_cast<Fn>(original);
  return true;
}

template <typename Replacement, typename Original>
inline bool attach_interpose_symbol(const char* symbol,
                                    Replacement replacement,
                                    w1::h00k::hook_handle& handle_out,
                                    Original& original_out) {
  return attach_interpose_symbol(symbol, reinterpret_cast<void*>(replacement), handle_out, original_out);
}

inline bool attach_inline_instrument(const char* symbol,
                                     const char* module,
                                     w1::h00k::prehook_fn prehook,
                                     w1::h00k::hook_handle& handle_out) {
  w1::h00k::hook_request request{};
  request.target.kind = w1::h00k::hook_target_kind::symbol;
  request.target.symbol = symbol;
  request.target.module = module;
  request.kind = w1::h00k::hook_kind::instrument;
  request.prehook = prehook;
  request.preferred = w1::h00k::hook_technique::inline_trampoline;
  request.allowed = w1::h00k::technique_mask(w1::h00k::hook_technique::inline_trampoline);
  request.selection = w1::h00k::hook_selection::strict;

  auto result = w1::h00k::attach(request, nullptr);
  if (!result.error.ok()) {
    return false;
  }

  handle_out = result.handle;
  return true;
}

inline bool attach_inline_replace(const char* symbol,
                                  const char* module,
                                  void* replacement,
                                  w1::h00k::hook_handle& handle_out,
                                  void*& original_out) {
  w1::h00k::hook_request request{};
  request.target.kind = w1::h00k::hook_target_kind::symbol;
  request.target.symbol = symbol;
  request.target.module = module;
  request.replacement = replacement;
  request.preferred = w1::h00k::hook_technique::inline_trampoline;
  request.allowed = w1::h00k::technique_mask(w1::h00k::hook_technique::inline_trampoline);
  request.selection = w1::h00k::hook_selection::strict;

  void* original = nullptr;
  auto result = w1::h00k::attach(request, &original);
  if (!result.error.ok()) {
    return false;
  }

  handle_out = result.handle;
  original_out = original;
  return true;
}

template <typename Fn>
inline bool attach_inline_replace(const char* symbol,
                                  const char* module,
                                  void* replacement,
                                  w1::h00k::hook_handle& handle_out,
                                  Fn& original_out) {
  void* original = nullptr;
  if (!attach_inline_replace(symbol, module, replacement, handle_out, original)) {
    return false;
  }
  original_out = reinterpret_cast<Fn>(original);
  return true;
}

template <typename Replacement, typename Original>
inline bool attach_inline_replace(const char* symbol,
                                  const char* module,
                                  Replacement replacement,
                                  w1::h00k::hook_handle& handle_out,
                                  Original& original_out) {
  return attach_inline_replace(symbol, module, reinterpret_cast<void*>(replacement), handle_out, original_out);
}

inline void detach_if_attached(w1::h00k::hook_handle& handle) {
  if (handle.id == 0) {
    return;
  }
  (void)w1::h00k::detach(handle);
  handle = {};
}

} // namespace w1::monitor::backend::hook_helpers
