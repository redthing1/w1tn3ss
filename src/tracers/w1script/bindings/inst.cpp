#include "inst.hpp"

#include <QBDI.h>

namespace w1::tracers::script::bindings {

namespace {

constexpr QBDI::AnalysisType k_default_analysis = QBDI::AnalysisType::ANALYSIS_INSTRUCTION;

} // namespace

void setup_inst_bindings(sol::state& lua, sol::table& w1_module) {
  sol::table inst = lua.create_table();

  inst.set_function(
      "current",
      [](QBDI::VM* vm, sol::optional<QBDI::AnalysisType> analysis_type) -> const QBDI::InstAnalysis* {
        if (!vm) {
          return nullptr;
        }
        return vm->getInstAnalysis(analysis_type.value_or(k_default_analysis));
      }
  );

  inst.set_function("disasm", [](QBDI::VM* vm) -> sol::optional<std::string> {
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

  w1_module["inst"] = inst;
}

} // namespace w1::tracers::script::bindings
