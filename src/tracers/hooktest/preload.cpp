#include <cstdlib>
#include <cstring>
#include <memory>
#include <iomanip>
#include <sstream>

#include "QBDIPreload.h"
#include <redlog.hpp>

#include <w1tn3ss/engine/tracer_engine.hpp>
#include <w1tn3ss/hooking/hook_manager.hpp>
#include <w1tn3ss/util/env_config.hpp>
#include <w1tn3ss/util/module_range_index.hpp>
#include <w1tn3ss/util/module_scanner.hpp>
#include <w1tn3ss/util/signal_handler.hpp>
#include <w1tn3ss/util/stderr_write.hpp>
#include <w1tn3ss/util/safe_memory.hpp>
#include <w1tn3ss/abi/calling_convention_factory.hpp>

class hooktest_tracer {
public:
  explicit hooktest_tracer(bool use_abi = false) : use_abi_(use_abi) {
    log_.inf("hooktest tracer created", redlog::field("use_abi", use_abi_));
  }

  bool initialize(w1::tracer_engine<hooktest_tracer>& engine) {
    log_.inf("initializing hooktest tracer");
    log_.inf("argument extraction mode", redlog::field("use_abi", use_abi_ ? "calling convention" : "direct register"));

    // scan and index modules
    log_.inf("scanning modules");
    auto modules = scanner_.scan_executable_modules();
    index_.rebuild_from_modules(std::move(modules));

    log_.inf("module scan complete", redlog::field("modules", index_.size()));

    // create hook manager
    hook_manager_ = std::make_unique<w1::hooking::hook_manager>(engine.get_vm());

    // find our test target
    const w1::util::module_info* target_module = nullptr;
    index_.visit_all([&](const w1::util::module_info& mod) {
      if (mod.path.find("hook_test_target") != std::string::npos) {
        target_module = &mod;
      }
    });

    if (!target_module) {
      log_.err("could not find hook_test_target module");
      return false;
    }

    log_.inf(
        "found target module", redlog::field("base", "0x%lx", target_module->base_address),
        redlog::field("size", "0x%lx", target_module->size)
    );

    // hook the functions by offset
    setup_hooks(target_module->base_address);

    return true;
  }

  void shutdown() {
    log_.inf("shutting down hooktest tracer");
    if (hook_manager_) {
      hook_manager_->remove_all_hooks();
    }
  }

  const char* get_name() const { return "hooktest"; }

private:
  void setup_hooks(QBDI::rword base_addr) {
    // known offsets from nm output
    struct hook_target {
      const char* name;
      QBDI::rword offset;
    };

    hook_target targets[] = {
        {"calculate_secret", 0x840},
        {"format_message", 0x88c},
        {"allocate_buffer", 0x8e4},
        {"compare_strings", 0x940},
        {"unsafe_copy", 0x98c}
    };

    // hook each function by address
    for (const auto& target : targets) {
      QBDI::rword addr = base_addr + target.offset;

      std::string func_name = target.name;
      auto hook_id = hook_manager_->hook_addr(
          addr,
          [this, func_name](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, QBDI::rword address) {
            return on_function_hook(vm, gpr, fpr, address, func_name.c_str());
          }
      );

      if (hook_id > 0) {
        log_.inf(
            "hooked function", redlog::field("name", target.name), redlog::field("address", "0x%lx", addr),
            redlog::field("hook_id", hook_id)
        );
      } else {
        log_.err(
            "failed to hook function", redlog::field("name", target.name), redlog::field("address", "0x%lx", addr)
        );
      }
    }

    // demonstrate module+offset hooking
    auto module_hook_id = hook_manager_->hook_module(
        "hook_test_target", 0x840,
        [this](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, QBDI::rword address) {
          log_.dbg("module+offset hook triggered", redlog::field("address", "0x%lx", address));
          return QBDI::VMAction::CONTINUE;
        }
    );

    if (module_hook_id > 0) {
      log_.inf(
          "hooked via module+offset", redlog::field("module", "hook_test_target"), redlog::field("offset", "0x840"),
          redlog::field("hook_id", module_hook_id)
      );
    }

    // demonstrate range hooking
    QBDI::rword text_start = base_addr;
    QBDI::rword text_end = base_addr + 0x1000; // first 4kb

    auto range_hook_id = hook_manager_->hook_range(
        text_start, text_end,
        [this, text_start](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, QBDI::rword address) {
          // only log every 100th instruction to avoid spam
          static int count = 0;
          if (++count % 100 == 0) {
            log_.dbg(
                "range hook", redlog::field("address", "0x%lx", address),
                redlog::field("offset", "0x%lx", address - text_start), redlog::field("count", count)
            );
          }
          return QBDI::VMAction::CONTINUE;
        }
    );

    if (range_hook_id > 0) {
      log_.inf(
          "hooked range", redlog::field("start", "0x%lx", text_start), redlog::field("end", "0x%lx", text_end),
          redlog::field("hook_id", range_hook_id)
      );

      // store for later removal demo
      range_hook_id_ = range_hook_id;
    }
  }

  QBDI::VMAction on_function_hook(
      QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, QBDI::rword address, const char* func_name
  ) {
    // get calling convention
    auto cc = w1::abi::create_default_calling_convention();
    // log the function call
    log_.inf("hook triggered", redlog::field("function", func_name), redlog::field("address", "0x%lx", address));

    // get instruction analysis
    try {
      const QBDI::InstAnalysis* inst = vm->getInstAnalysis();
      if (inst) {
        log_.dbg(
            "instruction info", redlog::field("disasm", inst->disassembly), redlog::field("mnemonic", inst->mnemonic),
            redlog::field("size", inst->instSize)
        );
      }
    } catch (...) {
      log_.dbg("exception getting instruction analysis");
    }

    // extract arguments using configured method
    if (use_abi_ && cc) {
      // use calling convention api
      w1::abi::calling_convention_base::extraction_context ctx;
      ctx.gpr = gpr;
      ctx.fpr = fpr;
      ctx.read_stack = [vm](uint64_t addr) -> uint64_t {
        uint64_t value = 0;
        // note: proper memory reading would need vm->readMemory() but simplified here
        // in real use, hook manager has the vm instance
        return value;
      };

      // extract first 4 arguments
      auto args = cc->extract_integer_args(ctx, 4);

      log_.inf(
          "arguments (calling convention)", redlog::field("platform", cc->get_name().c_str()),
          redlog::field("arg1", "0x%lx", args.size() > 0 ? args[0] : 0),
          redlog::field("arg2", "0x%lx", args.size() > 1 ? args[1] : 0),
          redlog::field("arg3", "0x%lx", args.size() > 2 ? args[2] : 0),
          redlog::field("arg4", "0x%lx", args.size() > 3 ? args[3] : 0)
      );

      // log calling convention details once
      if (!cc_logged_) {
        log_.inf(
            "calling convention details", redlog::field("name", cc->get_name().c_str()),
            redlog::field("stack_alignment", cc->get_stack_alignment()),
            redlog::field("red_zone_size", cc->get_red_zone_size())
        );
        cc_logged_ = true;
      }
    } else {
      // use direct register access
#if defined(__aarch64__)
      log_.inf(
          "arguments (direct arm64)", redlog::field("x0", "0x%lx", gpr->x0), redlog::field("x1", "0x%lx", gpr->x1),
          redlog::field("x2", "0x%lx", gpr->x2), redlog::field("x3", "0x%lx", gpr->x3)
      );
#elif defined(__x86_64__)
#if defined(_WIN32)
      log_.inf(
          "arguments (direct x64 windows)", redlog::field("rcx", "0x%lx", gpr->rcx),
          redlog::field("rdx", "0x%lx", gpr->rdx), redlog::field("r8", "0x%lx", gpr->r8),
          redlog::field("r9", "0x%lx", gpr->r9)
      );
#else
      log_.inf(
          "arguments (direct x64 sysv)", redlog::field("rdi", "0x%lx", gpr->rdi),
          redlog::field("rsi", "0x%lx", gpr->rsi), redlog::field("rdx", "0x%lx", gpr->rdx),
          redlog::field("rcx", "0x%lx", gpr->rcx)
      );
#endif
#endif
    }

    // print stack pointer and program counter
    QBDI::rword sp = QBDI_GPR_GET(gpr, QBDI::REG_SP);
    QBDI::rword pc = QBDI_GPR_GET(gpr, QBDI::REG_PC);
    log_.dbg("context", redlog::field("sp", "0x%lx", sp), redlog::field("pc", "0x%lx", pc));

    // demonstrate hook removal after a few calls
    hook_count_++;
    if (hook_count_ == 10 && range_hook_id_ > 0) {
      log_.inf("removing range hook after 10 function calls");
      if (hook_manager_->remove_hook(range_hook_id_)) {
        log_.inf("range hook removed successfully");
        range_hook_id_ = 0;
      }
    }

    // special handling for specific functions
    if (strcmp(func_name, "calculate_secret") == 0) {
      if (use_abi_ && cc) {
        // extract arguments using calling convention
        w1::abi::calling_convention_base::extraction_context ctx;
        ctx.gpr = gpr;
        ctx.fpr = fpr;
        ctx.read_stack = [vm](uint64_t addr) -> uint64_t {
          uint64_t value = 0;
          // note: proper memory reading would need vm->readMemory() but simplified here
          return value;
        };

        auto args = cc->extract_integer_args(ctx, 2);
        if (args.size() >= 2) {
          int a = static_cast<int>(args[0]);
          int b = static_cast<int>(args[1]);
          log_.inf(
              "calculate_secret params (abi)", redlog::field("a", a), redlog::field("b", b),
              redlog::field("expected_result", 3 * a + 2 * b)
          );
        }
      } else {
        // direct register access
        int a = 0;
        int b = 0;
#if defined(__aarch64__)
        a = static_cast<int>(gpr->x0);
        b = static_cast<int>(gpr->x1);
#elif defined(__x86_64__) && defined(_WIN32)
        a = static_cast<int>(gpr->rcx);
        b = static_cast<int>(gpr->rdx);
#elif defined(__x86_64__)
        a = static_cast<int>(gpr->rdi);
        b = static_cast<int>(gpr->rsi);
#endif
        log_.inf(
            "calculate_secret params (direct)", redlog::field("a", a), redlog::field("b", b),
            redlog::field("expected_result", 3 * a + 2 * b)
        );
      }
    } else if (strcmp(func_name, "format_message") == 0) {
      if (use_abi_ && cc) {
        // extract arguments using calling convention
        w1::abi::calling_convention_base::extraction_context ctx;
        ctx.gpr = gpr;
        ctx.fpr = fpr;
        ctx.read_stack = [vm](uint64_t addr) -> uint64_t {
          uint64_t value = 0;
          // note: proper memory reading would need vm->readMemory() but simplified here
          return value;
        };

        auto args = cc->extract_integer_args(ctx, 3);
        if (args.size() >= 3) {
          QBDI::rword buffer_ptr = args[0];
          QBDI::rword name_ptr = args[1];
          int value = static_cast<int>(args[2]);

          auto name_str = w1::util::safe_memory::read_string(vm, name_ptr, 256);
          log_.inf(
              "format_message params (abi)", redlog::field("buffer", "0x%lx", buffer_ptr),
              redlog::field("name_ptr", "0x%lx", name_ptr),
              redlog::field("name", name_str ? name_str->c_str() : "<read failed>"), redlog::field("value", value)
          );
        }
      } else {
        // direct register access
        QBDI::rword buffer_ptr = 0;
        QBDI::rword name_ptr = 0;
        int value = 0;
#if defined(__aarch64__)
        buffer_ptr = gpr->x0;
        name_ptr = gpr->x1;
        value = static_cast<int>(gpr->x2);
#elif defined(__x86_64__) && defined(_WIN32)
        buffer_ptr = gpr->rcx;
        name_ptr = gpr->rdx;
        value = static_cast<int>(gpr->r8);
#elif defined(__x86_64__)
        buffer_ptr = gpr->rdi;
        name_ptr = gpr->rsi;
        value = static_cast<int>(gpr->rdx);
#endif
        auto name_str = w1::util::safe_memory::read_string(vm, name_ptr, 256);
        log_.inf(
            "format_message params (direct)", redlog::field("buffer", "0x%lx", buffer_ptr),
            redlog::field("name_ptr", "0x%lx", name_ptr),
            redlog::field("name", name_str ? name_str->c_str() : "<read failed>"), redlog::field("value", value)
        );
      }
    } else if (strcmp(func_name, "allocate_buffer") == 0) {
      if (use_abi_ && cc) {
        w1::abi::calling_convention_base::extraction_context ctx;
        ctx.gpr = gpr;
        ctx.fpr = fpr;
        ctx.read_stack = [vm](uint64_t addr) -> uint64_t {
          uint64_t value = 0;
          // note: proper memory reading would need vm->readMemory() but simplified here
          return value;
        };

        auto args = cc->extract_integer_args(ctx, 1);
        if (!args.empty()) {
          size_t size = static_cast<size_t>(args[0]);
          log_.inf("allocate_buffer params (abi)", redlog::field("size", size));
        }
      } else {
        size_t size = 0;
#if defined(__aarch64__)
        size = static_cast<size_t>(gpr->x0);
#elif defined(__x86_64__) && defined(_WIN32)
        size = static_cast<size_t>(gpr->rcx);
#elif defined(__x86_64__)
        size = static_cast<size_t>(gpr->rdi);
#endif
        log_.inf("allocate_buffer params (direct)", redlog::field("size", size));
      }
    } else if (strcmp(func_name, "compare_strings") == 0) {
      if (use_abi_ && cc) {
        w1::abi::calling_convention_base::extraction_context ctx;
        ctx.gpr = gpr;
        ctx.fpr = fpr;
        ctx.read_stack = [vm](uint64_t addr) -> uint64_t {
          uint64_t value = 0;
          // note: proper memory reading would need vm->readMemory() but simplified here
          return value;
        };

        auto args = cc->extract_integer_args(ctx, 2);
        if (args.size() >= 2) {
          QBDI::rword str1_ptr = args[0];
          QBDI::rword str2_ptr = args[1];

          auto str1 = w1::util::safe_memory::read_string(vm, str1_ptr, 256);
          auto str2 = w1::util::safe_memory::read_string(vm, str2_ptr, 256);

          log_.inf(
              "compare_strings params (abi)", redlog::field("str1_ptr", "0x%lx", str1_ptr),
              redlog::field("str1", str1 ? str1->c_str() : "<read failed>"),
              redlog::field("str2_ptr", "0x%lx", str2_ptr),
              redlog::field("str2", str2 ? str2->c_str() : "<read failed>")
          );
        }
      } else {
        QBDI::rword str1_ptr = 0;
        QBDI::rword str2_ptr = 0;
#if defined(__aarch64__)
        str1_ptr = gpr->x0;
        str2_ptr = gpr->x1;
#elif defined(__x86_64__) && defined(_WIN32)
        str1_ptr = gpr->rcx;
        str2_ptr = gpr->rdx;
#elif defined(__x86_64__)
        str1_ptr = gpr->rdi;
        str2_ptr = gpr->rsi;
#endif
        auto str1 = w1::util::safe_memory::read_string(vm, str1_ptr, 256);
        auto str2 = w1::util::safe_memory::read_string(vm, str2_ptr, 256);

        log_.inf(
            "compare_strings params (direct)", redlog::field("str1_ptr", "0x%lx", str1_ptr),
            redlog::field("str1", str1 ? str1->c_str() : "<read failed>"), redlog::field("str2_ptr", "0x%lx", str2_ptr),
            redlog::field("str2", str2 ? str2->c_str() : "<read failed>")
        );
      }
    } else if (strcmp(func_name, "unsafe_copy") == 0) {
      if (use_abi_ && cc) {
        w1::abi::calling_convention_base::extraction_context ctx;
        ctx.gpr = gpr;
        ctx.fpr = fpr;
        ctx.read_stack = [vm](uint64_t addr) -> uint64_t {
          uint64_t value = 0;
          // note: proper memory reading would need vm->readMemory() but simplified here
          return value;
        };

        auto args = cc->extract_integer_args(ctx, 2);
        if (args.size() >= 2) {
          QBDI::rword dst_ptr = args[0];
          QBDI::rword src_ptr = args[1];

          auto src_str = w1::util::safe_memory::read_string(vm, src_ptr, 256);
          log_.wrn(
              "unsafe_copy detected - security risk (abi)", redlog::field("dst", "0x%lx", dst_ptr),
              redlog::field("src_ptr", "0x%lx", src_ptr),
              redlog::field("src_content", src_str ? src_str->c_str() : "<read failed>")
          );
        }
      } else {
        QBDI::rword dst_ptr = 0;
        QBDI::rword src_ptr = 0;
#if defined(__aarch64__)
        dst_ptr = gpr->x0;
        src_ptr = gpr->x1;
#elif defined(__x86_64__) && defined(_WIN32)
        dst_ptr = gpr->rcx;
        src_ptr = gpr->rdx;
#elif defined(__x86_64__)
        dst_ptr = gpr->rdi;
        src_ptr = gpr->rsi;
#endif
        auto src_str = w1::util::safe_memory::read_string(vm, src_ptr, 256);
        log_.wrn(
            "unsafe_copy detected - security risk (direct)", redlog::field("dst", "0x%lx", dst_ptr),
            redlog::field("src_ptr", "0x%lx", src_ptr),
            redlog::field("src_content", src_str ? src_str->c_str() : "<read failed>")
        );
      }
    }

    return QBDI::VMAction::CONTINUE;
  }

private:
  redlog::logger log_ = redlog::get_logger("hooktest.tracer");
  w1::util::module_scanner scanner_;
  w1::util::module_range_index index_;
  std::unique_ptr<w1::hooking::hook_manager> hook_manager_;
  uint32_t range_hook_id_ = 0;
  int hook_count_ = 0;
  bool use_abi_ = false;
  bool cc_logged_ = false;
};

// globals
static std::unique_ptr<hooktest_tracer> g_tracer;
static std::unique_ptr<w1::tracer_engine<hooktest_tracer>> g_engine;

namespace {

void shutdown_tracer() {
  if (!g_tracer) {
    return;
  }

  try {
    g_tracer->shutdown();
  } catch (...) {
    const char* error_msg = "hooktest: tracer shutdown failed\n";
    w1::util::stderr_write(error_msg);
  }
}

} // anonymous namespace

extern "C" {

QBDIPRELOAD_INIT;

QBDI_EXPORT int qbdipreload_on_run(QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop) {
  auto log = redlog::get_logger("hooktest.preload");

  log.inf("qbdipreload_on_run called");

  // get config
  w1::util::env_config config_loader("HOOKTEST_");
  int verbose = config_loader.get<int>("VERBOSE", 0);
  bool use_abi = config_loader.get<bool>("USE_ABI", false);

  log.inf("hooktest configuration", redlog::field("verbose", verbose), redlog::field("use_abi", use_abi));

  // set log level based on verbosity
  if (verbose >= 4) {
    redlog::set_level(redlog::level::pedantic);
  } else if (verbose >= 3) {
    redlog::set_level(redlog::level::debug);
  } else if (verbose >= 2) {
    redlog::set_level(redlog::level::trace);
  } else if (verbose >= 1) {
    redlog::set_level(redlog::level::verbose);
  } else {
    redlog::set_level(redlog::level::info);
  }

  // initialize signal handling for emergency shutdown
  w1::tn3ss::signal_handler::config sig_config;
  sig_config.context_name = "hooktest";
  sig_config.log_signals = verbose;

  if (w1::tn3ss::signal_handler::initialize(sig_config)) {
    w1::tn3ss::signal_handler::register_cleanup(
        shutdown_tracer,
        200, // high priority
        "hooktest_shutdown"
    );
    log.inf("signal handling initialized for tracer shutdown");
  } else {
    log.wrn("failed to initialize signal handling - shutdown on signal unavailable");
  }

  // create tracer
  log.inf("creating hooktest tracer");
  g_tracer = std::make_unique<hooktest_tracer>(use_abi);

  // create engine
  log.inf("creating tracer engine");
  g_engine = std::make_unique<w1::tracer_engine<hooktest_tracer>>(vm, *g_tracer);

  // initialize tracer
  g_tracer->initialize(*g_engine);

  // instrument
  log.inf("instrumenting engine");
  if (!g_engine->instrument()) {
    log.error("engine instrumentation failed");
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  log.inf("engine instrumentation successful");

  // run engine
  log.inf("running engine", redlog::field("start", "0x%08x", start), redlog::field("stop", "0x%08x", stop));
  if (!g_engine->run(start, stop)) {
    log.error("engine run failed");
    return QBDIPRELOAD_ERR_STARTUP_FAILED;
  }

  // execution doesn't reach here if it works (vm run jumps)
  log.inf("qbdipreload_on_run completed");

  return QBDIPRELOAD_NO_ERROR;
}

QBDI_EXPORT int qbdipreload_on_exit(int status) { return QBDIPRELOAD_NO_ERROR; }

QBDI_EXPORT int qbdipreload_on_start(void* main) { return QBDIPRELOAD_NOT_HANDLED; }

QBDI_EXPORT int qbdipreload_on_premain(void* gprCtx, void* fpuCtx) { return QBDIPRELOAD_NOT_HANDLED; }

QBDI_EXPORT int qbdipreload_on_main(int argc, char** argv) { return QBDIPRELOAD_NOT_HANDLED; }

} // extern "C"