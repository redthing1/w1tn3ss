#include "w1asmr/arch.hpp"

#include <cctype>
#include <string>

namespace w1::asmr {

namespace {

std::string trim_lower(std::string_view input) {
  size_t start = 0;
  while (start < input.size() && std::isspace(static_cast<unsigned char>(input[start])) != 0) {
    ++start;
  }
  size_t end = input.size();
  while (end > start && std::isspace(static_cast<unsigned char>(input[end - 1])) != 0) {
    --end;
  }

  std::string output;
  output.reserve(end - start);
  for (size_t i = start; i < end; ++i) {
    output.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(input[i]))));
  }
  return output;
}

} // namespace

std::string_view arch_to_string(arch value) {
  switch (value) {
  case arch::x86:
    return "x86";
  case arch::x64:
    return "x64";
  case arch::arm64:
    return "arm64";
  }
  return "unknown";
}

result<arch> parse_arch(std::string_view text) {
  std::string value = trim_lower(text);
  if (value.empty()) {
    return error_result<arch>(error_code::invalid_argument, "architecture value is empty");
  }

  if (value == "x86" || value == "i386" || value == "i686") {
    return ok_result(arch::x86);
  }
  if (value == "x64" || value == "x86_64" || value == "amd64") {
    return ok_result(arch::x64);
  }
  if (value == "arm64" || value == "aarch64") {
    return ok_result(arch::arm64);
  }

  return error_result<arch>(error_code::unsupported, "unsupported architecture: " + value);
}

result<arch> detect_host_arch() {
#if defined(__x86_64__) || defined(_M_X64)
  return ok_result(arch::x64);
#elif defined(__aarch64__) || defined(_M_ARM64)
  return ok_result(arch::arm64);
#elif defined(__i386__) || defined(_M_IX86)
  return ok_result(arch::x86);
#else
  return error_result<arch>(error_code::unsupported, "unsupported host architecture");
#endif
}

} // namespace w1::asmr
