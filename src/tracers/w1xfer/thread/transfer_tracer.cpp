#include "transfer_tracer.hpp"

#include <sstream>
#include <utility>

namespace w1xfer {
namespace {

std::string format_hex(uint64_t value) {
  std::ostringstream oss;
  oss << "0x" << std::hex << value;
  return oss.str();
}

std::string format_symbol_name(const transfer_symbol& symbol) {
  std::string name = symbol.demangled_name.empty() ? symbol.symbol_name : symbol.demangled_name;
  if (symbol.symbol_offset != 0) {
    name += "+";
    name += format_hex(symbol.symbol_offset);
  }
  return name;
}

struct endpoint_summary {
  std::string module;
  std::string symbol;
};

endpoint_summary describe_endpoint(const transfer_engine& engine, const transfer_config& config, uint64_t address) {
  endpoint_summary out;
  if (!config.enrich.modules && !config.enrich.symbols) {
    return out;
  }

  auto endpoint = engine.resolve_endpoint(address);
  if (!endpoint) {
    return out;
  }

  if (!endpoint->module_name.empty()) {
    out.module = endpoint->module_name;
    if (!endpoint->symbol && endpoint->module_offset != 0) {
      out.module += "+";
      out.module += format_hex(endpoint->module_offset);
    }
  }

  if (endpoint->symbol) {
    out.symbol = format_symbol_name(*endpoint->symbol);
  }

  return out;
}

void log_transfer_event(
    redlog::logger& log, const char* label, const transfer_engine& engine, const transfer_config& config,
    uint64_t source, uint64_t target
) {
  endpoint_summary source_info = describe_endpoint(engine, config, source);
  endpoint_summary target_info = describe_endpoint(engine, config, target);

  if (!source_info.module.empty() || !target_info.module.empty() || !source_info.symbol.empty() ||
      !target_info.symbol.empty()) {
    log.vrb(
        label, redlog::field("source", "0x%016llx", source), redlog::field("target", "0x%016llx", target),
        redlog::field("source_module", source_info.module), redlog::field("source_symbol", source_info.symbol),
        redlog::field("target_module", target_info.module), redlog::field("target_symbol", target_info.symbol)
    );
  } else {
    log.vrb(label, redlog::field("source", "0x%016llx", source), redlog::field("target", "0x%016llx", target));
  }
}

} // namespace

transfer_tracer::transfer_tracer(std::shared_ptr<transfer_engine> engine, transfer_config config)
    : engine_(std::move(engine)), config_(std::move(config)) {
  if (config_.verbose > 0) {
    log_.inf(
        "transfer tracer created", redlog::field("output", config_.output.path),
        redlog::field("capture_registers", config_.capture.registers),
        redlog::field("capture_stack", config_.capture.stack), redlog::field("enrich_modules", config_.enrich.modules),
        redlog::field("enrich_symbols", config_.enrich.symbols),
        redlog::field("analyze_apis", config_.enrich.analyze_apis)
    );
  }
}

void transfer_tracer::on_thread_start(w1::trace_context& ctx, const w1::thread_event& event) {
  (void) event;
  if (initialized_ || !engine_) {
    return;
  }

  log_.inf("initializing transfer tracer");

  const bool needs_modules = config_.enrich.modules || config_.enrich.symbols ||
                             (config_.output.emit_metadata && !config_.output.path.empty());
  if (needs_modules) {
    log_.inf("module tracking enabled");
  }

  engine_->attach(ctx);

  if (config_.verbose > 0) {
    log_.inf("transfer tracer initialized successfully");
  }
  initialized_ = true;
}

void transfer_tracer::on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event) {
  (void) ctx;
  (void) event;
  if (!engine_) {
    return;
  }

  log_.inf("shutting down transfer tracer");
  engine_->shutdown();

  const auto& stats = engine_->stats();
  log_.inf(
      "transfer collection completed", redlog::field("total_calls", stats.total_calls),
      redlog::field("total_returns", stats.total_returns), redlog::field("unique_targets", stats.unique_call_targets),
      redlog::field("max_depth", stats.max_call_depth)
  );
}

void transfer_tracer::on_exec_transfer_call(
    w1::trace_context& ctx, const w1::exec_transfer_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  (void) vm;
  (void) state;
  if (!engine_) {
    return;
  }

  engine_->record_call(ctx, event, gpr, fpr);

  if (config_.verbose > 0) {
    log_transfer_event(log_, "call transfer detected", *engine_, config_, event.source_address, event.target_address);
  }
}

void transfer_tracer::on_exec_transfer_return(
    w1::trace_context& ctx, const w1::exec_transfer_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  (void) vm;
  (void) state;
  if (!engine_) {
    return;
  }

  engine_->record_return(ctx, event, gpr, fpr);

  if (config_.verbose > 0) {
    log_transfer_event(log_, "return transfer detected", *engine_, config_, event.source_address, event.target_address);
  }
}

} // namespace w1xfer
