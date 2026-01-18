#include "w1dump/process_dumper.hpp"

#include "w1dump/register_dumper.hpp"

#include <chrono>
#include <fstream>
#include <vector>

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

#ifdef _WIN32
#include <w1base/windows_clean.hpp>
#include <process.h>
#else
#include <unistd.h>
#endif

namespace w1::dump {

redlog::logger process_dumper::log_ = redlog::get_logger("w1.dump.process");

process_dump process_dumper::dump_current(
    QBDI::VMInstanceRef vm, const util::memory_reader& memory, uint64_t thread_id, const QBDI::GPRState& gpr,
    const QBDI::FPRState& fpr, const dump_options& options
) {
  log_.inf("starting process dump");

  process_dump dump;

  auto now = std::chrono::system_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());

  dump.metadata.version = 1;
  dump.metadata.timestamp = duration.count();
  dump.metadata.os = get_os_name();
  dump.metadata.arch = get_arch_name();
  dump.metadata.pointer_size = get_pointer_size();
  dump.metadata.pid = get_pid();
  dump.metadata.process_name = get_process_name();

  dump.thread = register_dumper::capture_thread_state(gpr, fpr, thread_id);
  dump.modules = memory_dumper::dump_modules();
  dump.regions = memory_dumper::dump_memory_regions(vm, memory, gpr, options);

  log_.inf(
      "process dump completed", redlog::field("modules", dump.modules.size()),
      redlog::field("regions", dump.regions.size())
  );

  return dump;
}

void process_dumper::save_dump(const process_dump& dump, const std::string& path) {
  log_.inf("saving dump to file", redlog::field("path", path));

  try {
    nlohmann::json json = dump;
    auto msgpack = nlohmann::json::to_msgpack(json);

    std::ofstream file(path, std::ios::binary);
    if (!file) {
      log_.err("failed to open file for writing", redlog::field("path", path));
      throw std::runtime_error("failed to open dump file");
    }

    file.write(reinterpret_cast<const char*>(msgpack.data()), static_cast<std::streamsize>(msgpack.size()));
    file.close();

    log_.inf("dump saved", redlog::field("path", path), redlog::field("size", msgpack.size()));
  } catch (const std::exception& e) {
    log_.err("failed to save dump", redlog::field("path", path), redlog::field("error", e.what()));
    throw;
  }
}

process_dump process_dumper::load_dump(const std::string& path) {
  log_.inf("loading dump from file", redlog::field("path", path));

  try {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
      log_.err("failed to open file for reading", redlog::field("path", path));
      throw std::runtime_error("failed to open dump file");
    }

    std::vector<uint8_t> msgpack((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    auto json = nlohmann::json::from_msgpack(msgpack);
    process_dump dump = json.get<process_dump>();

    log_.inf(
        "dump loaded", redlog::field("path", path), redlog::field("version", dump.metadata.version),
        redlog::field("modules", dump.modules.size()), redlog::field("regions", dump.regions.size())
    );

    return dump;
  } catch (const std::exception& e) {
    log_.err("failed to load dump", redlog::field("path", path), redlog::field("error", e.what()));
    throw;
  }
}

std::string process_dumper::get_os_name() {
#if defined(_WIN32) || defined(_WIN64)
  return "windows";
#elif defined(__linux__)
  return "linux";
#elif defined(__APPLE__)
  return "darwin";
#else
  return "unknown";
#endif
}

std::string process_dumper::get_arch_name() {
#if defined(__x86_64__) || defined(_M_X64)
  return "x86_64";
#elif defined(__i386__) || defined(_M_IX86)
  return "x86";
#elif defined(__aarch64__) || defined(_M_ARM64)
  return "arm64";
#elif defined(__arm__) || defined(_M_ARM)
  return "arm";
#else
  return "unknown";
#endif
}

uint32_t process_dumper::get_pointer_size() { return static_cast<uint32_t>(sizeof(void*)); }

uint64_t process_dumper::get_pid() {
#ifdef _WIN32
  return static_cast<uint64_t>(_getpid());
#else
  return static_cast<uint64_t>(getpid());
#endif
}

std::string process_dumper::get_process_name() {
  char process_name[512] = {0};

#ifdef __APPLE__
  uint32_t size = sizeof(process_name);
  if (_NSGetExecutablePath(process_name, &size) == 0) {
    std::string full_path(process_name);
    size_t pos = full_path.find_last_of("/");
    if (pos != std::string::npos) {
      return full_path.substr(pos + 1);
    }
    return full_path;
  }
#elif defined(__linux__)
  if (readlink("/proc/self/exe", process_name, sizeof(process_name) - 1) > 0) {
    std::string full_path(process_name);
    size_t pos = full_path.find_last_of("/");
    if (pos != std::string::npos) {
      return full_path.substr(pos + 1);
    }
    return full_path;
  }
#elif defined(_WIN32)
  char full_path[MAX_PATH];
  if (GetModuleFileNameA(NULL, full_path, MAX_PATH) > 0) {
    std::string path_str(full_path);
    size_t pos = path_str.find_last_of("\\");
    if (pos != std::string::npos) {
      return path_str.substr(pos + 1);
    }
    return path_str;
  }
#else
  return "unknown";
#endif

  return "unknown";
}

} // namespace w1::dump
