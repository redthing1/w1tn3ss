#pragma once

#include "../config/script_config.hpp"
#include "output_state.hpp"

#include "w1analysis/abi_dispatcher.hpp"
#include "w1analysis/symbol_lookup.hpp"
#include "w1runtime/module_catalog.hpp"
#include "w1runtime/memory_reader.hpp"

#include <QBDI.h>
#include <redlog.hpp>

#include <string>

namespace w1::tracers::script::runtime {

class script_context {
public:
  script_context(
      QBDI::VM* vm, const script_config& config, w1::runtime::module_catalog* modules,
      const w1::util::memory_reader* memory, uint64_t thread_id, std::string thread_name
  );

  QBDI::VM* vm() const { return vm_; }
  const script_config& config() const { return config_; }
  w1::runtime::module_catalog& modules() const { return *modules_; }
  const w1::util::memory_reader& memory() const { return *memory_; }
  w1::analysis::symbol_lookup& symbols() { return symbol_lookup_; }
  const w1::analysis::symbol_lookup& symbols() const { return symbol_lookup_; }
  w1::analysis::abi_dispatcher& abi() { return abi_dispatcher_; }
  output_state& output() { return output_; }
  uint64_t thread_id() const { return thread_id_; }
  const std::string& thread_name() const { return thread_name_; }

  bool refresh_modules();
  void shutdown();

private:
  script_config config_{};
  QBDI::VM* vm_ = nullptr;
  w1::runtime::module_catalog* modules_ = nullptr;
  const w1::util::memory_reader* memory_ = nullptr;
  w1::analysis::symbol_lookup symbol_lookup_{};
  w1::analysis::abi_dispatcher abi_dispatcher_{};
  output_state output_{};
  uint64_t thread_id_ = 0;
  std::string thread_name_;
  redlog::logger logger_;
};

} // namespace w1::tracers::script::runtime
