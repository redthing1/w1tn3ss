#include "signature_scanning.hpp"
#include <p1ll/scripting/lua_bindings.hpp>
#include <w1tn3ss/hooking/hook_manager.hpp>
#include <redlog.hpp>

namespace w1::tracers::script::bindings {

void setup_signature_scanning(sol::state& lua, sol::table& w1_module) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up signature scanning functions");

  // first, setup p1ll bindings in the lua state
  logger.dbg("registering p1ll lua bindings");
  p1ll::scripting::setup_p1ll_bindings(lua);

  // now create convenience functions that combine p1ll sig scanning with w1tn3ss hooking

  // hook_sig: find signature and hook it
  w1_module.set_function(
      "hook_sig",
      [&logger, &lua, &w1_module](sol::object sig_obj, sol::protected_function handler) -> sol::optional<uint32_t> {
        try {
          void* hook_mgr_ptr = w1_module["_hook_manager"];
          auto hook_mgr = static_cast<w1::hooking::hook_manager*>(hook_mgr_ptr);

          // call p1ll's search_signature through lua
          sol::table p1_module = lua["p1"];
          sol::protected_function search_sig = p1_module["search_signature"];

          // handle both string patterns and signature objects
          sol::protected_function_result search_result;
          if (sig_obj.is<std::string>()) {
            std::string pattern = sig_obj.as<std::string>();
            logger.dbg("searching for signature pattern to hook", redlog::field("pattern", pattern));
            search_result = search_sig(pattern);
          } else {
            // assume it's a signature object from p1.sig()
            logger.dbg("searching for signature object to hook");
            sol::table sig_table = sig_obj.as<sol::table>();
            std::string pattern = sig_table["pattern"];

            // check for filter
            sol::object filter = sig_table["filter"];
            if (filter.valid()) {
              search_result = search_sig(pattern, filter);
            } else {
              search_result = search_sig(pattern);
            }
          }

          if (!search_result.valid()) {
            sol::error err = search_result;
            logger.err("signature search failed", redlog::field("error", err.what()));
            return sol::nullopt;
          }

          // extract results
          sol::table results = search_result;
          if (results.size() == 0) {
            logger.err("signature not found for hooking");
            return sol::nullopt;
          }

          // get first result
          sol::table first_result = results[1];
          uint64_t addr = first_result["address"];

          logger.dbg("hooking signature match", redlog::field("address", "0x%lx", addr));

          // create hook using the signature address
          auto cpp_handler = [handler, &logger](
                                 QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, QBDI::rword addr
                             ) -> QBDI::VMAction {
            try {
              auto result = handler(vm, gpr, fpr, addr);

              if (!result.valid()) {
                sol::error err = result;
                logger.err("lua hook handler error", redlog::field("error", err.what()));
                return QBDI::VMAction::CONTINUE;
              }

              sol::optional<QBDI::VMAction> action = result;
              if (action) {
                return *action;
              }

              return QBDI::VMAction::CONTINUE;
            } catch (const std::exception& e) {
              logger.err("exception in hook handler", redlog::field("error", e.what()));
              return QBDI::VMAction::CONTINUE;
            }
          };

          uint32_t hook_id = hook_mgr->hook_addr(addr, cpp_handler);
          if (hook_id == 0) {
            logger.err("failed to create hook for signature");
            return sol::nullopt;
          }

          return hook_id;
        } catch (const std::exception& e) {
          logger.err("error during signature hook", redlog::field("error", e.what()));
          return sol::nullopt;
        }
      }
  );

  // hook_all_sigs: find all occurrences of a signature and hook them
  w1_module.set_function(
      "hook_all_sigs",
      [&logger, &lua, &w1_module](sol::object sig_obj, sol::protected_function handler) -> sol::optional<sol::table> {
        try {
          void* hook_mgr_ptr = w1_module["_hook_manager"];
          auto hook_mgr = static_cast<w1::hooking::hook_manager*>(hook_mgr_ptr);

          // call p1ll's search_signature through lua
          sol::table p1_module = lua["p1"];
          sol::protected_function search_sig = p1_module["search_signature"];

          // handle both string patterns and signature objects
          sol::protected_function_result search_result;
          if (sig_obj.is<std::string>()) {
            std::string pattern = sig_obj.as<std::string>();
            logger.dbg("searching for all signature patterns to hook", redlog::field("pattern", pattern));
            search_result = search_sig(pattern);
          } else {
            // assume it's a signature object from p1.sig()
            logger.dbg("searching for all signature objects to hook");
            sol::table sig_table = sig_obj.as<sol::table>();
            std::string pattern = sig_table["pattern"];

            // check for filter
            sol::object filter = sig_table["filter"];
            if (filter.valid()) {
              search_result = search_sig(pattern, filter);
            } else {
              search_result = search_sig(pattern);
            }
          }

          if (!search_result.valid()) {
            sol::error err = search_result;
            logger.err("signature search failed", redlog::field("error", err.what()));
            return sol::nullopt;
          }

          // extract results
          sol::table results = search_result;
          if (results.size() == 0) {
            logger.err("signature not found for hooking");
            return sol::nullopt;
          }

          // create result table with hook IDs
          sol::table hook_ids = lua.create_table();

          // hook each result
          for (size_t i = 1; i <= results.size(); ++i) {
            sol::table result = results[i];
            uint64_t addr = result["address"];

            logger.dbg("hooking signature match", redlog::field("index", i), redlog::field("address", "0x%lx", addr));

            // create hook using the signature address
            auto cpp_handler = [handler, &logger](
                                   QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, QBDI::rword addr
                               ) -> QBDI::VMAction {
              try {
                auto result = handler(vm, gpr, fpr, addr);

                if (!result.valid()) {
                  sol::error err = result;
                  logger.err("lua hook handler error", redlog::field("error", err.what()));
                  return QBDI::VMAction::CONTINUE;
                }

                sol::optional<QBDI::VMAction> action = result;
                if (action) {
                  return *action;
                }

                return QBDI::VMAction::CONTINUE;
              } catch (const std::exception& e) {
                logger.err("exception in hook handler", redlog::field("error", e.what()));
                return QBDI::VMAction::CONTINUE;
              }
            };

            uint32_t hook_id = hook_mgr->hook_addr(addr, cpp_handler);
            if (hook_id != 0) {
              hook_ids[i] = hook_id;
            }
          }

          logger.dbg("hooked signatures", redlog::field("count", hook_ids.size()));
          return hook_ids;
        } catch (const std::exception& e) {
          logger.err("error during signature hook", redlog::field("error", e.what()));
          return sol::nullopt;
        }
      }
  );

  logger.dbg("signature scanning functions registered");
}

} // namespace w1::tracers::script::bindings