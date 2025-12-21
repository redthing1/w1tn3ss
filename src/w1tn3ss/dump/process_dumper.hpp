#pragma once

#include "w1tn3ss/dump/dump_format.hpp"
#include "w1tn3ss/dump/memory_dumper.hpp"

#include <QBDI.h>
#include <redlog.hpp>

#include <string>

namespace w1::dump {

class process_dumper {
public:
  static process_dump dump_current(
      QBDI::VMInstanceRef vm, const util::memory_reader& memory, uint64_t thread_id, const QBDI::GPRState& gpr,
      const QBDI::FPRState& fpr, const dump_options& options = {}
  );

  static void save_dump(const process_dump& dump, const std::string& path);
  static process_dump load_dump(const std::string& path);

private:
  static redlog::logger log_;

  static std::string get_os_name();
  static std::string get_arch_name();
  static uint32_t get_pointer_size();
  static std::string get_process_name();
  static uint64_t get_pid();
};

} // namespace w1::dump
