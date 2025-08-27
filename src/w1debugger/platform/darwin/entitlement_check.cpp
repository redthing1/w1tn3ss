#include "darwin_internal.hpp"
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

namespace w1::debugger::darwin {

bool check_has_debugger_entitlement() {
  // check if we're running with the debugger entitlement
  // we can check this by attempting to get our own code signing info
  SecCodeRef code = nullptr;
  OSStatus status = SecCodeCopySelf(kSecCSDefaultFlags, &code);
  if (status != errSecSuccess) {
    return false;
  }

  CFDictionaryRef info = nullptr;
  status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info);
  CFRelease(code);

  if (status != errSecSuccess) {
    return false;
  }

  bool has_entitlement = false;
  if (info) {
    // check for entitlements dictionary
    CFDictionaryRef entitlements = (CFDictionaryRef) CFDictionaryGetValue(info, kSecCodeInfoEntitlementsDict);
    if (entitlements) {
      // look for com.apple.security.cs.debugger
      CFStringRef key = CFSTR("com.apple.security.cs.debugger");
      if (CFDictionaryContainsKey(entitlements, key)) {
        CFBooleanRef value = (CFBooleanRef) CFDictionaryGetValue(entitlements, key);
        has_entitlement = (value == kCFBooleanTrue);
      }
    }
    CFRelease(info);
  }

  return has_entitlement;
}

} // namespace w1::debugger::darwin
