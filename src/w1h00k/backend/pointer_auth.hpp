#pragma once

#if defined(__APPLE__) && __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

namespace w1::h00k::backend {

inline void* sanitize_original_pointer(void* value) {
#if defined(__APPLE__) && __has_feature(ptrauth_calls)
  value = ptrauth_strip(value, ptrauth_key_asia);
  value = ptrauth_sign_unauthenticated(value, ptrauth_key_asia, 0);
  return value;
#else
  return value;
#endif
}

inline void* sign_replacement_pointer(void* value, void* slot) {
#if defined(__APPLE__) && __has_feature(ptrauth_calls)
  value = ptrauth_strip(value, ptrauth_key_asia);
  value = ptrauth_sign_unauthenticated(value, ptrauth_key_asia, slot);
  return value;
#else
  (void)slot;
  return value;
#endif
}

} // namespace w1::h00k::backend
