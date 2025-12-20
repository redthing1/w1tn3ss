#pragma once

#include "../script_config.hpp"
#include "output_state.hpp"

#include <w1tn3ss/util/module_range_index.hpp>
#include <w1tn3ss/util/module_scanner.hpp>
#include <w1tn3ss/symbols/symbol_resolver.hpp>
#include <w1tn3ss/symbols/symbol_lookup.hpp>
#include <w1tn3ss/hooking/hook_manager.hpp>
#include <w1tn3ss/gadget/gadget_executor.hpp>

#include <p1ll/core/context.hpp>

#include <QBDI.h>
#include <redlog.hpp>

#include <memory>
#include <string>

namespace w1::tracers::script::runtime {

class script_context {
public:
  script_context(QBDI::VM* vm, const config& cfg);

  QBDI::VM* vm() const { return vm_; }
  const config& cfg() const { return cfg_; }

  w1::util::module_range_index& module_index() { return module_index_; }
  const w1::util::module_range_index& module_index() const { return module_index_; }

  w1::symbols::symbol_resolver& symbol_resolver() { return *symbol_resolver_; }
  const w1::symbols::symbol_resolver& symbol_resolver() const { return *symbol_resolver_; }
  w1::symbols::symbol_lookup& symbol_lookup() { return *symbol_lookup_; }
  const w1::symbols::symbol_lookup& symbol_lookup() const { return *symbol_lookup_; }

  std::shared_ptr<w1::hooking::hook_manager> hook_manager() { return hook_manager_; }
  std::shared_ptr<w1tn3ss::gadget::gadget_executor> gadget_executor() { return gadget_executor_; }
  std::shared_ptr<p1ll::context> p1ll_context() { return p1ll_context_; }

  output_state& output() { return *output_; }

  bool refresh_modules();
  void shutdown();

private:
  config cfg_;
  QBDI::VM* vm_ = nullptr;

  w1::util::module_scanner module_scanner_;
  w1::util::module_range_index module_index_;
  std::unique_ptr<w1::symbols::symbol_resolver> symbol_resolver_;
  std::unique_ptr<w1::symbols::symbol_lookup> symbol_lookup_;

  std::shared_ptr<w1::hooking::hook_manager> hook_manager_;
  std::shared_ptr<w1tn3ss::gadget::gadget_executor> gadget_executor_;
  std::shared_ptr<p1ll::context> p1ll_context_;
  std::unique_ptr<output_state> output_;

  redlog::logger logger_;
};

} // namespace w1::tracers::script::runtime
