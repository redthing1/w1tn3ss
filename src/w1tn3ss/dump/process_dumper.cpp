#include "process_dumper.hpp"
#include "register_dumper.hpp"
#include "memory_dumper.hpp"
#include <chrono>
#include <fstream>

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

#ifdef _WIN32
#include <w1common/windows_clean.hpp>
#include <process.h>
#else
#include <unistd.h>
#endif

namespace w1 {
namespace dump {

redlog::logger process_dumper::log_ = redlog::get_logger("w1.dump.process");

w1dump process_dumper::dump_current(
    QBDI::VMInstanceRef vm, const QBDI::GPRState& gpr, const QBDI::FPRState& fpr, const dump_options& options
) {
  log_.inf("starting process dump");

  w1dump dump;

  // fill metadata
  log_.trc("capturing process metadata");
  dump.metadata.version = 1;
  // store timestamp as milliseconds since epoch for portability
  auto now = std::chrono::system_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
  dump.metadata.timestamp = duration.count();
  dump.metadata.os = get_os_name();
  dump.metadata.arch = get_arch_name();
  dump.metadata.pointer_size = get_pointer_size();
#ifdef _WIN32
  dump.metadata.pid = _getpid();
#else
  dump.metadata.pid = getpid();
#endif

  // get process name
  char process_name[256] = {0};
#ifdef __APPLE__
  uint32_t size = sizeof(process_name);
  if (_NSGetExecutablePath(process_name, &size) == 0) {
    // extract just the basename
    std::string full_path(process_name);
    size_t pos = full_path.find_last_of("/");
    if (pos != std::string::npos) {
      dump.metadata.process_name = full_path.substr(pos + 1);
    } else {
      dump.metadata.process_name = full_path;
    }
  }
#elif defined(__linux__)
  if (readlink("/proc/self/exe", process_name, sizeof(process_name) - 1) > 0) {
    std::string full_path(process_name);
    size_t pos = full_path.find_last_of("/");
    if (pos != std::string::npos) {
      dump.metadata.process_name = full_path.substr(pos + 1);
    } else {
      dump.metadata.process_name = full_path;
    }
  }
#elif defined(_WIN32)
  char full_path[MAX_PATH];
  if (GetModuleFileNameA(NULL, full_path, MAX_PATH) > 0) {
    std::string path_str(full_path);
    size_t pos = path_str.find_last_of("\\");
    if (pos != std::string::npos) {
      dump.metadata.process_name = path_str.substr(pos + 1);
    } else {
      dump.metadata.process_name = path_str;
    }
  } else {
    dump.metadata.process_name = "unknown";
  }
#else
  dump.metadata.process_name = "unknown";
#endif

  log_.dbg(
      "metadata captured", redlog::field("os", dump.metadata.os), redlog::field("arch", dump.metadata.arch),
      redlog::field("pid", dump.metadata.pid), redlog::field("process", dump.metadata.process_name)
  );

  // capture thread state
  log_.trc("capturing thread state");
  dump.thread = register_dumper::capture_thread_state(gpr, fpr);

  // dump modules
  log_.trc("collecting module information");
  dump.modules = memory_dumper::dump_modules(options);

  // dump memory regions
  log_.trc("dumping memory regions");
  dump.regions = memory_dumper::dump_memory_regions(vm, gpr, options);

  log_.inf(
      "process dump completed", redlog::field("modules", dump.modules.size()),
      redlog::field("regions", dump.regions.size())
  );

  return dump;
}

void process_dumper::save_dump(const w1dump& dump, const std::string& path) {
  log_.inf("saving dump to file", redlog::field("path", path));

  try {
    // convert to json
    log_.dbg("converting dump to json format");
    nlohmann::json j = dump;

    // serialize to msgpack
    log_.dbg("serializing to msgpack format");
    auto msgpack = nlohmann::json::to_msgpack(j);
    log_.dbg("msgpack serialization complete", redlog::field("size", msgpack.size()));

    // write to file
    log_.trc("writing dump to disk");
    std::ofstream file(path, std::ios::binary);
    if (!file) {
      log_.err("failed to open file for writing", redlog::field("path", path));
      throw std::runtime_error("failed to open dump file");
    }

    file.write(reinterpret_cast<const char*>(msgpack.data()), msgpack.size());
    file.close();

    log_.inf("dump saved successfully", redlog::field("path", path), redlog::field("size", msgpack.size()));

  } catch (const std::exception& e) {
    log_.err("failed to save dump", redlog::field("path", path), redlog::field("error", e.what()));
    throw;
  }
}

w1dump process_dumper::load_dump(const std::string& path) {
  log_.inf("loading dump from file", redlog::field("path", path));

  try {
    // read file
    std::ifstream file(path, std::ios::binary);
    if (!file) {
      log_.err("failed to open file for reading", redlog::field("path", path));
      throw std::runtime_error("failed to open dump file");
    }

    // read all data
    log_.trc("reading msgpack data from file");
    std::vector<uint8_t> msgpack((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    log_.dbg("read msgpack data", redlog::field("size", msgpack.size()));

    // deserialize from msgpack
    log_.dbg("deserializing msgpack to json");
    auto j = nlohmann::json::from_msgpack(msgpack);

    // convert to dump struct
    log_.dbg("converting json to dump structure");
    w1dump dump = j.get<w1dump>();

    log_.inf(
        "dump loaded successfully", redlog::field("path", path), redlog::field("version", dump.metadata.version),
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

uint32_t process_dumper::get_pointer_size() { return sizeof(void*); }

} // namespace dump
} // namespace w1