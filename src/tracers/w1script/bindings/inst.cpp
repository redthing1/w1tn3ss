#include "inst.hpp"

#include <QBDI.h>
#include <redlog.hpp>

namespace w1::tracers::script::bindings {

namespace {

constexpr QBDI::AnalysisType k_default_analysis = QBDI::AnalysisType::ANALYSIS_INSTRUCTION;

} // namespace

void setup_inst_bindings(sol::state& lua, sol::table& w1_module) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up inst bindings");

  sol::table inst_module = lua.create_table();

  inst_module.set_function(
      "current",
      [](QBDI::VM* vm, sol::optional<QBDI::AnalysisType> analysis_type) -> const QBDI::InstAnalysis* {
        if (!vm) {
          return nullptr;
        }
        return vm->getInstAnalysis(analysis_type.value_or(k_default_analysis));
      }
  );

  inst_module.set_function("disasm", [](QBDI::VM* vm) -> sol::optional<std::string> {
    if (!vm) {
      return sol::nullopt;
    }
    auto analysis = vm->getInstAnalysis(QBDI::AnalysisType::ANALYSIS_INSTRUCTION |
                                        QBDI::AnalysisType::ANALYSIS_DISASSEMBLY);
    if (!analysis || !analysis->disassembly) {
      return sol::nullopt;
    }
    return std::string(analysis->disassembly);
  });

  w1_module["inst"] = inst_module;
}

} // namespace w1::tracers::script::bindings
