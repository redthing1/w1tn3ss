#include "instraware_common.hpp"

#include <cstdlib>
#include <cstring>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <mach/mach_time.h>
#include <time.h>
#else
#include <time.h>
#endif

namespace instraware {
namespace {

std::string escape_json(const std::string& input) {
  std::string out;
  out.reserve(input.size());
  for (char c : input) {
    switch (c) {
    case '\\':
      out += "\\\\";
      break;
    case '"':
      out += "\\\"";
      break;
    case '\n':
      out += "\\n";
      break;
    case '\r':
      out += "\\r";
      break;
    case '\t':
      out += "\\t";
      break;
    default:
      if (static_cast<unsigned char>(c) < 0x20) {
        out += "?";
      } else {
        out += c;
      }
      break;
    }
  }
  return out;
}

} // namespace

uint64_t now_ns() {
#if defined(_WIN32)
  static LARGE_INTEGER freq = [] {
    LARGE_INTEGER value;
    QueryPerformanceFrequency(&value);
    return value;
  }();
  LARGE_INTEGER counter;
  QueryPerformanceCounter(&counter);
  return static_cast<uint64_t>((counter.QuadPart * 1000000000ULL) / freq.QuadPart);
#elif defined(__APPLE__)
  static mach_timebase_info_data_t timebase = [] {
    mach_timebase_info_data_t info{};
    mach_timebase_info(&info);
    return info;
  }();
  uint64_t t = mach_absolute_time();
  return (t * timebase.numer) / timebase.denom;
#else
  struct timespec ts;
#ifdef CLOCK_MONOTONIC_RAW
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
#else
  clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
  return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + static_cast<uint64_t>(ts.tv_nsec);
#endif
}

const char* platform() {
#if defined(_WIN32)
  return "windows";
#elif defined(__APPLE__)
  return "macos";
#elif defined(__linux__)
  return "linux";
#else
  return "unknown";
#endif
}

const char* arch() {
#if defined(__x86_64__) || defined(_M_X64)
  return "x86_64";
#elif defined(__aarch64__) || defined(_M_ARM64)
  return "arm64";
#else
  return "unknown";
#endif
}

args parse_args(int argc, char** argv) {
  args parsed;
  for (int i = 1; i < argc; ++i) {
    const char* arg = argv[i];
    if (std::strncmp(arg, "--iterations=", 13) == 0) {
      parsed.iterations = std::strtoull(arg + 13, nullptr, 10);
    } else if (std::strncmp(arg, "--json-out=", 11) == 0) {
      parsed.json_out = arg + 11;
    } else if (std::strcmp(arg, "--verbose") == 0 || std::strcmp(arg, "-v") == 0) {
      parsed.verbose = true;
    }
  }
  return parsed;
}

FILE* open_output(const char* path) {
  if (!path || path[0] == '\0') {
    return stdout;
  }

  FILE* out = std::fopen(path, "a");
  if (!out) {
    return stdout;
  }
  return out;
}

void close_output(FILE* file) {
  if (file && file != stdout) {
    std::fclose(file);
  }
}

void emit_json(const result& entry, FILE* out) {
  if (!out) {
    out = stdout;
  }
  std::string notes = escape_json(entry.notes);
  std::fprintf(
      out,
      "{\"test_id\":\"%s\",\"platform\":\"%s\",\"arch\":\"%s\",\"iterations\":%llu,"
      "\"score\":%.6f,\"confidence\":%.6f,\"anomalies\":%llu,\"notes\":\"%s\"}\n",
      entry.test_id.c_str(), entry.platform.c_str(), entry.arch.c_str(),
      static_cast<unsigned long long>(entry.iterations), entry.score, entry.confidence,
      static_cast<unsigned long long>(entry.anomalies), notes.c_str()
  );
  std::fflush(out);
}

} // namespace instraware
