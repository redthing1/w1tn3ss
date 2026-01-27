#include "dump_recorder.hpp"

#include <string_view>

#include <redlog.hpp>

#include "w1runtime/module_catalog.hpp"

namespace w1dump {
namespace {

const char* trigger_name(dump_trigger_mode mode) { return dump_config::trigger_name(mode); }

const w1::runtime::module_info* find_module_exact(
    const std::vector<w1::runtime::module_info>& modules, std::string_view name
) {
  if (name.empty()) {
    return nullptr;
  }
  for (const auto& module : modules) {
    if (module.name == name) {
      return &module;
    }
  }
  return nullptr;
}

const w1::runtime::module_info* find_module_by_path(
    const std::vector<w1::runtime::module_info>& modules, std::string_view name
) {
  if (name.empty()) {
    return nullptr;
  }
  for (const auto& module : modules) {
    if (!module.path.empty() && module.path.find(name) != std::string::npos) {
      return &module;
    }
  }
  return nullptr;
}

const w1::runtime::module_info* find_module_by_name_contains(
    const std::vector<w1::runtime::module_info>& modules, std::string_view name
) {
  if (name.empty()) {
    return nullptr;
  }
  for (const auto& module : modules) {
    if (module.name.find(name) != std::string::npos) {
      return &module;
    }
  }
  return nullptr;
}

const w1::runtime::module_info* find_main_module(const std::vector<w1::runtime::module_info>& modules) {
  for (const auto& module : modules) {
    if (module.is_main) {
      return &module;
    }
  }
  return nullptr;
}

const w1::runtime::module_info* locate_module(
    const std::vector<w1::runtime::module_info>& modules, std::string_view name
) {
  if (name == "main") {
    if (const auto* main_mod = find_main_module(modules)) {
      return main_mod;
    }
  }
  if (const auto* exact = find_module_exact(modules, name)) {
    return exact;
  }
  if (const auto* path_match = find_module_by_path(modules, name)) {
    return path_match;
  }
  return find_module_by_name_contains(modules, name);
}

} // namespace

dump_recorder::dump_recorder(std::shared_ptr<dump_engine> engine) : engine_(std::move(engine)) {}

QBDI::VMAction dump_recorder::on_vm_start(
    w1::trace_context& ctx, const w1::sequence_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  (void) event;
  (void) state;

  if (!engine_ || engine_->dump_completed()) {
    return QBDI::VMAction::CONTINUE;
  }

  const auto& config = engine_->config();
  if (config.trigger == dump_trigger_mode::module_offset) {
    resolve_module_trigger(ctx);
  }

  if (config.trigger == dump_trigger_mode::entry) {
    engine_->dump_once(ctx, vm, gpr, fpr);
    return QBDI::VMAction::STOP;
  }

  return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction dump_recorder::on_instruction_pre(
    w1::trace_context& ctx, const w1::instruction_event& event, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  if (!engine_ || engine_->dump_completed()) {
    return QBDI::VMAction::CONTINUE;
  }

  if (!should_dump_on_instruction(event, ctx)) {
    return QBDI::VMAction::CONTINUE;
  }

  engine_->dump_once(ctx, vm, gpr, fpr);
  return QBDI::VMAction::STOP;
}

bool dump_recorder::dump_completed() const { return engine_ ? engine_->dump_completed() : false; }

bool dump_recorder::should_dump_on_instruction(const w1::instruction_event& event, w1::trace_context& ctx) {
  const auto& config = engine_->config();
  switch (config.trigger) {
  case dump_trigger_mode::entry:
    return false;
  case dump_trigger_mode::instruction:
    return true;
  case dump_trigger_mode::address:
    if (!config.trigger_address) {
      if (!logged_invalid_trigger_) {
        logged_invalid_trigger_ = true;
        redlog::get_logger("w1dump.trigger")
            .err("trigger address not configured", redlog::field("trigger", trigger_name(config.trigger)));
      }
      return false;
    }
    return event.address == config.trigger_address.value();
  case dump_trigger_mode::module_offset: {
    auto resolved = resolve_module_trigger(ctx);
    if (!resolved) {
      return false;
    }
    return event.address == resolved.value();
  }
  }

  return false;
}

std::optional<uint64_t> dump_recorder::resolve_module_trigger(w1::trace_context& ctx) {
  const auto& config = engine_->config();
  if (config.trigger != dump_trigger_mode::module_offset) {
    return std::nullopt;
  }

  if (resolved_address_) {
    return resolved_address_;
  }

  if (config.trigger_module.empty() || !config.trigger_offset) {
    if (!logged_invalid_trigger_) {
      logged_invalid_trigger_ = true;
      redlog::get_logger("w1dump.trigger")
          .err("trigger module/offset not configured", redlog::field("trigger", trigger_name(config.trigger)));
    }
    return std::nullopt;
  }

  auto& modules = ctx.modules();
  uint64_t module_version = modules.version();
  if (resolved_module_version_ == module_version) {
    return resolved_address_;
  }

  auto list = modules.list_modules();
  const auto* module = locate_module(list, config.trigger_module);
  if (!module) {
    modules.refresh();
    list = modules.list_modules();
    module_version = modules.version();
    module = locate_module(list, config.trigger_module);
  }

  resolved_module_version_ = module_version;

  if (!module) {
    if (!logged_missing_module_) {
      logged_missing_module_ = true;
      redlog::get_logger("w1dump.trigger")
          .wrn("trigger module not found", redlog::field("module", config.trigger_module));
    }
    return std::nullopt;
  }

  resolved_address_ = module->base_address + config.trigger_offset.value();
  redlog::get_logger("w1dump.trigger")
      .inf(
          "resolved trigger address", redlog::field("module", module->name),
          redlog::field("base", "0x%llx", module->base_address),
          redlog::field("offset", "0x%llx", config.trigger_offset.value()),
          redlog::field("address", "0x%llx", resolved_address_.value())
      );
  return resolved_address_;
}

} // namespace w1dump
