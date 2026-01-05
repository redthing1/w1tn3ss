#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include <QBDI.h>

#include "w1tn3ss/util/memory_reader.hpp"

namespace w1::analysis {

enum class abi_kind { system_v_amd64, windows_amd64, aarch64, x86, unknown };

struct call_argument {
  uint64_t raw_value = 0;
  bool from_register = false;
  bool is_valid = false;
};

struct abi_dispatcher_config {
  abi_kind kind = abi_kind::unknown;
  bool enable_stack_reads = true;
};

class abi_dispatcher {
public:
  abi_dispatcher();
  explicit abi_dispatcher(abi_dispatcher_config config);

  abi_kind kind() const { return config_.kind; }

  std::vector<call_argument> extract_arguments(
      const util::memory_reader& memory, const QBDI::GPRState* gpr, size_t argument_count
  ) const;

  uint64_t extract_return_value(const QBDI::GPRState* gpr) const;

  static abi_kind detect_native_kind();

private:
  std::optional<uint64_t> read_stack_value(
      const util::memory_reader& memory, uint64_t stack_address, size_t word_size
  ) const;

  abi_dispatcher_config config_{};
};

} // namespace w1::analysis
