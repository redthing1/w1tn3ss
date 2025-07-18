#pragma once

#include <QBDI.h>
#include <string>
#include "dump_format.hpp"
#include "memory_dumper.hpp"

namespace w1 {
namespace dump {

class process_dumper {
public:
  // dump current process state
  static w1dump dump_current(
      QBDI::VMInstanceRef vm, const QBDI::GPRState& gpr, const QBDI::FPRState& fpr, const dump_options& options = {}
  );

  // save/load using msgpack
  static void save_dump(const w1dump& dump, const std::string& path);
  static w1dump load_dump(const std::string& path);

private:
  static redlog::logger log_;

  // get platform info
  static std::string get_os_name();
  static std::string get_arch_name();
  static uint32_t get_pointer_size();
};

} // namespace dump
} // namespace w1