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

} // namespace

transfer_tracer::transfer_tracer(transfer_config config)
    : config_(std::move(config)), pipeline_(config_), log_(redlog::get_logger("w1xfer.tracer")) {
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
  if (initialized_) {
    return;
  }

  log_.inf("initializing transfer tracer");
  const bool needs_modules = config_.enrich.modules || config_.enrich.symbols || config_.enrich.analyze_apis ||
                             (config_.output.emit_metadata && !config_.output.path.empty());
  if (needs_modules) {
    log_.inf("initializing module tracking");
  }
  pipeline_.initialize(ctx);
  if (needs_modules) {
    log_.inf("module tracking initialized");
  }
  if (config_.verbose > 0) {
    log_.inf("transfer tracer initialized successfully");
  }
  initialized_ = true;
}

void transfer_tracer::on_thread_stop(w1::trace_context& ctx, const w1::thread_event& event) {
  (void) ctx;
  (void) event;
  log_.inf("shutting down transfer tracer");
  const auto& stats = pipeline_.stats();
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
  pipeline_.record_call(ctx, event, gpr, fpr);
  if (config_.verbose > 0) {
    std::string source_module;
    std::string target_module;
    std::string source_symbol;
    std::string target_symbol;

    if (config_.enrich.modules || config_.enrich.symbols) {
      if (auto endpoint = pipeline_.resolve_endpoint(event.source_address)) {
        if (!endpoint->module_name.empty()) {
          source_module = endpoint->module_name;
          if (!endpoint->symbol && endpoint->module_offset != 0) {
            source_module += "+";
            source_module += format_hex(endpoint->module_offset);
          }
        }
        if (endpoint->symbol) {
          source_symbol = format_symbol_name(*endpoint->symbol);
        }
      }

      if (auto endpoint = pipeline_.resolve_endpoint(event.target_address)) {
        if (!endpoint->module_name.empty()) {
          target_module = endpoint->module_name;
          if (!endpoint->symbol && endpoint->module_offset != 0) {
            target_module += "+";
            target_module += format_hex(endpoint->module_offset);
          }
        }
        if (endpoint->symbol) {
          target_symbol = format_symbol_name(*endpoint->symbol);
        }
      }
    }

    if (!source_module.empty() || !target_module.empty() || !source_symbol.empty() || !target_symbol.empty()) {
      log_.vrb(
          "call transfer detected", redlog::field("source", "0x%016llx", event.source_address),
          redlog::field("target", "0x%016llx", event.target_address), redlog::field("source_module", source_module),
          redlog::field("source_symbol", source_symbol), redlog::field("target_module", target_module),
          redlog::field("target_symbol", target_symbol)
      );
    } else {
      log_.vrb(
          "call transfer detected", redlog::field("source", "0x%016llx", event.source_address),
          redlog::field("target", "0x%016llx", event.target_address)
      );
    }
  }
}

void transfer_tracer::on_exec_transfer_return(
    w1::trace_context& ctx, const w1::exec_transfer_event& event, QBDI::VMInstanceRef vm, const QBDI::VMState* state,
    QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  (void) vm;
  (void) state;
  pipeline_.record_return(ctx, event, gpr, fpr);
  if (config_.verbose > 0) {
    std::string source_module;
    std::string target_module;
    std::string source_symbol;
    std::string target_symbol;

    if (config_.enrich.modules || config_.enrich.symbols) {
      if (auto endpoint = pipeline_.resolve_endpoint(event.source_address)) {
        if (!endpoint->module_name.empty()) {
          source_module = endpoint->module_name;
          if (!endpoint->symbol && endpoint->module_offset != 0) {
            source_module += "+";
            source_module += format_hex(endpoint->module_offset);
          }
        }
        if (endpoint->symbol) {
          source_symbol = format_symbol_name(*endpoint->symbol);
        }
      }

      if (auto endpoint = pipeline_.resolve_endpoint(event.target_address)) {
        if (!endpoint->module_name.empty()) {
          target_module = endpoint->module_name;
          if (!endpoint->symbol && endpoint->module_offset != 0) {
            target_module += "+";
            target_module += format_hex(endpoint->module_offset);
          }
        }
        if (endpoint->symbol) {
          target_symbol = format_symbol_name(*endpoint->symbol);
        }
      }
    }

    if (!source_module.empty() || !target_module.empty() || !source_symbol.empty() || !target_symbol.empty()) {
      log_.vrb(
          "return transfer detected", redlog::field("source", "0x%016llx", event.source_address),
          redlog::field("target", "0x%016llx", event.target_address), redlog::field("source_module", source_module),
          redlog::field("source_symbol", source_symbol), redlog::field("target_module", target_module),
          redlog::field("target_symbol", target_symbol)
      );
    } else {
      log_.vrb(
          "return transfer detected", redlog::field("source", "0x%016llx", event.source_address),
          redlog::field("target", "0x%016llx", event.target_address)
      );
    }
  }
}

} // namespace w1xfer
