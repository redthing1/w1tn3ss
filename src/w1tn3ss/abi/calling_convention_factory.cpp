#include "calling_convention_factory.hpp"
#include <redlog.hpp>
#include <stdexcept>

// include platform-specific convention headers
#if defined(__x86_64__) || defined(_M_X64)
#include "conventions/x86_64/system_v.hpp"
#include "conventions/x86_64/microsoft.hpp"
#elif defined(__i386__) || defined(_M_IX86)
#include "conventions/x86/cdecl.hpp"
// TODO: add when implemented
// #include "conventions/x86/stdcall.hpp"
// #include "conventions/x86/fastcall.hpp"
// #include "conventions/x86/thiscall.hpp"
#elif defined(__aarch64__) || defined(_M_ARM64)
#include "conventions/arm/aarch64_aapcs.hpp"
#elif defined(__arm__) || defined(_M_ARM)
// TODO: add when implemented
// #include "conventions/arm/arm32_aapcs.hpp"
#endif

namespace w1::abi {

calling_convention_factory& calling_convention_factory::instance() {
  static calling_convention_factory instance;
  static std::once_flag init_flag;
  std::call_once(init_flag, [&]() { instance.register_platform_conventions(); });
  return instance;
}

void calling_convention_factory::register_convention(
    calling_convention_id id, std::function<calling_convention_ptr()> creator
) {

  std::lock_guard<std::mutex> lock(mutex_);

  auto log = redlog::get_logger("w1.abi.factory");

  if (creators_.find(id) != creators_.end()) {
    log.wrn("overwriting existing convention registration", redlog::field("id", to_string(id)));
  }

  creators_[id] = creator;
  name_to_id_[to_string(id)] = id;

  log.dbg(
      "registered calling convention", redlog::field("id", to_string(id)), redlog::field("total", creators_.size())
  );
}

calling_convention_ptr calling_convention_factory::create(calling_convention_id id) const {
  std::lock_guard<std::mutex> lock(mutex_);

  auto it = creators_.find(id);
  if (it == creators_.end()) {
    throw std::runtime_error("calling convention not registered: " + to_string(id));
  }

  return it->second();
}

calling_convention_ptr calling_convention_factory::create_by_name(const std::string& name) const {
  std::lock_guard<std::mutex> lock(mutex_);

  auto it = name_to_id_.find(name);
  if (it == name_to_id_.end()) {
    throw std::runtime_error("unknown calling convention name: " + name);
  }

  return create(it->second);
}

calling_convention_ptr calling_convention_factory::create_default() const { return create(get_platform_default()); }

std::vector<calling_convention_id> calling_convention_factory::list_conventions() const {
  std::lock_guard<std::mutex> lock(mutex_);

  std::vector<calling_convention_id> result;
  result.reserve(creators_.size());

  for (const auto& [id, creator] : creators_) {
    result.push_back(id);
  }

  return result;
}

calling_convention_ptr calling_convention_factory::create_for_symbol(
    const std::string& module_name, const std::string& symbol_name
) const {

// platform-specific heuristics
#ifdef _WIN32
  // windows x86 decorated names
  if (symbol_name.size() > 0) {
    if (symbol_name[0] == '_' && symbol_name.find('@') != std::string::npos) {
      // _func@12 -> stdcall
      return create(calling_convention_id::X86_STDCALL);
    } else if (symbol_name[0] == '@' && symbol_name.find('@') != std::string::npos) {
      // @func@8 -> fastcall
      return create(calling_convention_id::X86_FASTCALL);
    } else if (symbol_name.find("@@") != std::string::npos) {
      // ?func@@ -> thiscall (c++ member)
      return create(calling_convention_id::X86_THISCALL);
    }
  }

  // windows api dlls typically use stdcall on x86
  if (module_name.find("kernel32") != std::string::npos || module_name.find("user32") != std::string::npos ||
      module_name.find("ntdll") != std::string::npos) {
#ifdef _WIN64
    return create(calling_convention_id::X86_64_MICROSOFT);
#else
    return create(calling_convention_id::X86_STDCALL);
#endif
  }
#endif

  // default to platform convention
  return create_default();
}

bool calling_convention_factory::is_registered(calling_convention_id id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return creators_.find(id) != creators_.end();
}

void calling_convention_factory::register_platform_conventions() {
  auto log = redlog::get_logger("w1.abi.factory");

// Register conventions based on current platform
#if defined(__x86_64__) || defined(_M_X64)
  register_x86_64_conventions();
#elif defined(__i386__) || defined(_M_IX86)
  register_x86_conventions();
#elif defined(__aarch64__) || defined(_M_ARM64)
  register_arm64_conventions();
#elif defined(__arm__) || defined(_M_ARM)
  register_arm_conventions();
#else
#error "Unsupported platform for calling conventions"
#endif

  // Determine platform string for logging
  const char* platform_str =
#if defined(__x86_64__) || defined(_M_X64)
      "x86_64"
#elif defined(__i386__) || defined(_M_IX86)
      "x86"
#elif defined(__aarch64__) || defined(_M_ARM64)
      "aarch64"
#elif defined(__arm__) || defined(_M_ARM)
      "arm"
#else
      "unknown"
#endif
      ;

  log.inf(
      "registered platform conventions", redlog::field("platform", platform_str),
      redlog::field("count", creators_.size())
  );
}

void calling_convention_factory::register_x86_conventions() {
#if defined(__i386__) || defined(_M_IX86)
  // x86 supports multiple calling conventions, especially on windows

  // cdecl is available on all platforms
  register_convention(calling_convention_id::X86_CDECL, []() { return std::make_shared<conventions::x86_cdecl>(); });

#ifdef _WIN32
// windows-specific calling conventions
// TODO: implement these conventions
/*
register_convention(
    calling_convention_id::X86_STDCALL,
    []() { return std::make_shared<conventions::x86_stdcall>(); }
);

register_convention(
    calling_convention_id::X86_FASTCALL,
    []() { return std::make_shared<conventions::x86_fastcall>(); }
);

register_convention(
    calling_convention_id::X86_THISCALL,
    []() { return std::make_shared<conventions::x86_thiscall>(); }
);

register_convention(
    calling_convention_id::X86_VECTORCALL,
    []() { return std::make_shared<conventions::x86_vectorcall>(); }
);
*/
#endif
#endif
}

void calling_convention_factory::register_x86_64_conventions() {
#if defined(__x86_64__) || defined(_M_X64)
  // x86-64 conventions depend on the operating system

#ifdef _WIN32
  // windows x64 uses microsoft convention
  register_convention(calling_convention_id::X86_64_MICROSOFT, []() {
    return std::make_shared<conventions::x86_64_microsoft>();
  });
// TODO: implement vectorcall for SIMD-heavy code
// register_convention(
//     calling_convention_id::X86_64_VECTORCALL,
//     []() { return std::make_shared<conventions::x86_64_vectorcall>(); }
// );
#else
  // unix platforms (linux, macos, bsd) use system v abi
  register_convention(calling_convention_id::X86_64_SYSTEM_V, []() {
    return std::make_shared<conventions::x86_64_system_v>();
  });
#endif
#endif
}

void calling_convention_factory::register_arm_conventions() {
#if defined(__arm__) || defined(_M_ARM)
// TODO: implement ARM32 conventions
/*
register_convention(
    calling_convention_id::ARM32_AAPCS,
    []() { return std::make_shared<conventions::arm32_aapcs>(); }
);
*/
#endif
}

void calling_convention_factory::register_arm64_conventions() {
#if defined(__aarch64__) || defined(_M_ARM64)
  // arm64 uses aapcs on both windows and unix
  register_convention(calling_convention_id::AARCH64_AAPCS, []() {
    return std::make_shared<conventions::aarch64_aapcs>();
  });

// windows arm64 has slight variations
#ifdef _WIN32
// TODO: implement windows arm64 specific convention if needed
#endif
#endif
}

calling_convention_id calling_convention_factory::get_platform_default() const {
#if defined(_WIN64)
  return calling_convention_id::X86_64_MICROSOFT;
#elif defined(__x86_64__)
  return calling_convention_id::X86_64_SYSTEM_V;
#elif defined(__aarch64__)
#ifdef _WIN32
  return calling_convention_id::AARCH64_WINDOWS;
#else
  return calling_convention_id::AARCH64_AAPCS;
#endif
#elif defined(__arm__)
  return calling_convention_id::ARM32_AAPCS;
#elif defined(_WIN32)
  // 32-bit windows defaults to stdcall for system apis
  return calling_convention_id::X86_STDCALL;
#elif defined(__i386__)
  return calling_convention_id::X86_CDECL;
#else
#error "unsupported platform for default calling convention"
#endif
}

} // namespace w1::abi