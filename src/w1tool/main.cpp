#include <iostream>
#include <string>
#include <cstdlib>
#include <iomanip>
#include <redlog/redlog.hpp>
#include "w1tn3ss.hpp"
#include "w1nj3ct.hpp"
#include "ext/args.hpp"
#include "../w1tn3ss/formats/drcov.hpp"

int cmd_inject(args::ValueFlag<std::string>& library_flag, 
               args::ValueFlag<std::string>& name_flag,
               args::ValueFlag<int>& pid_flag,
               args::ValueFlag<std::string>& binary_flag,
               args::ValueFlag<std::string>& tool_flag) {
    
    auto log = redlog::get_logger("w1tool.inject");
    
    // validate required arguments
    if (!library_flag) {
        log.error("library path required");
        return 1;
    }
    
    std::string lib_path = args::get(library_flag);
    w1::inject::result result;
    
    // tool-specific configuration is handled per injection method below
    if (tool_flag) {
        std::string tool_name = args::get(tool_flag);
        log.info("tool specified", redlog::field("tool", tool_name));
    }
    
    // determine injection method based on arguments
    if (binary_flag) {
        // launch injection
        std::string binary_path = args::get(binary_flag);
        log.info("launch injection starting", 
                 redlog::field("binary", binary_path),
                 redlog::field("library", lib_path));
        
        // use full config to pass environment variables
        w1::inject::config cfg;
        cfg.library_path = lib_path;
        cfg.injection_method = w1::inject::method::launch;
        cfg.binary_path = binary_path;
        
        // add environment variables if tool was specified
        if (tool_flag) {
            std::string tool_name = args::get(tool_flag);
            if (tool_name == "w1cov") {
                cfg.env_vars["W1COV_ENABLED"] = "1";
                cfg.env_vars["W1COV_EXCLUDE_SYSTEM"] = "1";
                cfg.env_vars["W1COV_DEBUG"] = "1";  // Enable debug output
                
                std::string output_file = "coverage.drcov";
                size_t last_slash = binary_path.find_last_of("/\\");
                std::string binary_name = (last_slash != std::string::npos) ? 
                    binary_path.substr(last_slash + 1) : binary_path;
                output_file = binary_name + ".drcov";
                cfg.env_vars["W1COV_OUTPUT_FILE"] = output_file;
                
                log.info("w1cov environment added to injection config", 
                         redlog::field("output_file", output_file));
            }
        }
        
        result = w1::inject::inject(cfg);
        
    } else if (pid_flag) {
        // runtime injection by pid
        int target_pid = args::get(pid_flag);
        log.info("runtime injection starting",
                 redlog::field("method", "pid"),
                 redlog::field("target_pid", target_pid),
                 redlog::field("library", lib_path));
        
        result = w1::inject::inject_library_runtime(lib_path, target_pid);
        
    } else if (name_flag) {
        // runtime injection by process name
        std::string process_name = args::get(name_flag);
        log.info("runtime injection starting",
                 redlog::field("method", "name"),
                 redlog::field("process_name", process_name),
                 redlog::field("library", lib_path));
        
        result = w1::inject::inject_library_runtime(lib_path, process_name);
        
    } else {
        log.error("target required: specify --pid, --name, or --binary");
        return 1;
    }
    
    // handle result
    if (result.success()) {
        if (result.target_pid > 0) {
            log.info("injection completed successfully",
                     redlog::field("target_pid", result.target_pid));
        } else {
            log.info("injection completed successfully");
        }
        return 0;
    } else {
        log.error("injection failed",
                  redlog::field("error", result.error_message));
        return 1;
    }
}

int cmd_inspect(args::ValueFlag<std::string>& binary_flag) {
    
    auto log = redlog::get_logger("w1tool.inspect");
    
    log.info("binary inspection starting");
    
    // get arguments  
    if (binary_flag) {
        std::string binary_path = args::get(binary_flag);
        log.info("target binary specified",
                 redlog::field("binary_path", binary_path));
        
        // future: initialize w1tn3ss engine and analyze binary
        w1::w1tn3ss engine;
        if (engine.initialize()) {
            log.debug("analysis engine ready for binary inspection");
            // todo: implement binary analysis logic
            log.warn("binary analysis not yet implemented");
            engine.shutdown();
        } else {
            log.error("failed to initialize analysis engine");
            return 1;
        }
    } else {
        log.error("binary path required for inspection");
        return 1;
    }
    
    
    return 0;
}

int cmd_drcov(args::ValueFlag<std::string>& file_flag,
              args::Flag& summary_flag,
              args::Flag& detailed_flag,
              args::ValueFlag<std::string>& module_flag) {
    
    auto log = redlog::get_logger("w1tool.drcov");
    
    if (!file_flag) {
        log.error("DrCov file path required");
        return 1;
    }
    
    std::string file_path = args::get(file_flag);
    log.info("analyzing DrCov file", redlog::field("file", file_path));
    
    try {
        // Read and parse the DrCov file
        auto coverage_data = drcov::read(file_path);
        
        // Print header information
        std::cout << "=== DrCov File Analysis ===\n";
        std::cout << "File: " << file_path << "\n";
        std::cout << "Version: " << coverage_data.header.version << "\n";
        std::cout << "Flavor: " << coverage_data.header.flavor << "\n";
        std::cout << "Module Table Version: " << static_cast<uint32_t>(coverage_data.module_version) << "\n";
        std::cout << "\n";
        
        // Print summary
        std::cout << "=== Summary ===\n";
        std::cout << "Total Modules: " << coverage_data.modules.size() << "\n";
        std::cout << "Total Basic Blocks: " << coverage_data.basic_blocks.size() << "\n";
        
        // Calculate coverage stats
        auto stats = coverage_data.get_coverage_stats();
        uint64_t total_coverage_bytes = 0;
        for (const auto& bb : coverage_data.basic_blocks) {
            total_coverage_bytes += bb.size;
        }
        std::cout << "Total Coverage: " << total_coverage_bytes << " bytes\n";
        std::cout << "\n";
        
        // Module summary
        std::cout << "=== Module Coverage ===\n";
        std::cout << std::left << std::setw(4) << "ID" 
                  << std::setw(8) << "Blocks" 
                  << std::setw(12) << "Size" 
                  << std::setw(20) << "Base Address" 
                  << "Name\n";
        std::cout << std::string(60, '-') << "\n";
        
        for (const auto& module : coverage_data.modules) {
            auto it = stats.find(module.id);
            size_t block_count = (it != stats.end()) ? it->second : 0;
            
            // Calculate total bytes for this module
            uint64_t module_bytes = 0;
            for (const auto& bb : coverage_data.basic_blocks) {
                if (bb.module_id == module.id) {
                    module_bytes += bb.size;
                }
            }
            
            std::cout << std::left << std::setw(4) << module.id
                      << std::setw(8) << block_count
                      << std::setw(12) << (std::to_string(module_bytes) + " bytes")
                      << "0x" << std::hex << std::setw(18) << module.base << std::dec
                      << module.path << "\n";
        }
        std::cout << "\n";
        
        // Detailed analysis if requested
        if (detailed_flag) {
            std::cout << "=== Detailed Basic Blocks ===\n";
            std::cout << std::left << std::setw(6) << "Module" 
                      << std::setw(12) << "Offset" 
                      << std::setw(8) << "Size" 
                      << "Absolute Address\n";
            std::cout << std::string(40, '-') << "\n";
            
            for (const auto& bb : coverage_data.basic_blocks) {
                if (bb.module_id < coverage_data.modules.size()) {
                    const auto& module = coverage_data.modules[bb.module_id];
                    uint64_t abs_addr = bb.absolute_address(module);
                    
                    std::cout << std::left << std::setw(6) << bb.module_id
                              << "0x" << std::hex << std::setw(10) << bb.start << std::dec
                              << std::setw(8) << bb.size
                              << "0x" << std::hex << abs_addr << std::dec << "\n";
                }
            }
            std::cout << "\n";
        }
        
        // Module-specific analysis if requested
        if (module_flag) {
            std::string module_filter = args::get(module_flag);
            std::cout << "=== Module-Specific Analysis: " << module_filter << " ===\n";
            
            // Find matching modules (by name substring)
            bool found = false;
            for (const auto& module : coverage_data.modules) {
                if (module.path.find(module_filter) != std::string::npos) {
                    found = true;
                    
                    std::cout << "Module ID: " << module.id << "\n";
                    std::cout << "Name: " << module.path << "\n";
                    std::cout << "Base: 0x" << std::hex << module.base << std::dec << "\n";
                    std::cout << "End: 0x" << std::hex << module.end << std::dec << "\n";
                    std::cout << "Size: " << (module.end - module.base) << " bytes\n";
                    
                    // Count blocks for this module
                    auto it = stats.find(module.id);
                    size_t block_count = (it != stats.end()) ? it->second : 0;
                    std::cout << "Covered Blocks: " << block_count << "\n";
                    
                    uint64_t module_bytes = 0;
                    for (const auto& bb : coverage_data.basic_blocks) {
                        if (bb.module_id == module.id) {
                            module_bytes += bb.size;
                        }
                    }
                    std::cout << "Covered Bytes: " << module_bytes << "\n";
                    std::cout << "\n";
                }
            }
            
            if (!found) {
                std::cout << "No modules found matching: " << module_filter << "\n";
            }
        }
        
        return 0;
        
    } catch (const drcov::parse_error& e) {
        log.error("failed to parse DrCov file", 
                  redlog::field("error", e.what()),
                  redlog::field("code", static_cast<int>(e.code())));
        return 1;
    } catch (const std::exception& e) {
        log.error("error analyzing DrCov file", redlog::field("error", e.what()));
        return 1;
    }
}

int main(int argc, char* argv[]) {
    auto log = redlog::get_logger("w1tool");
    
    // configure default logging level (warn for quiet operation)
    redlog::set_level(redlog::level::warn);
    
    log.debug("w1tool starting");
    
    args::ArgumentParser parser("w1tool - cross-platform dynamic binary analysis tool");
    parser.helpParams.proglineShowFlags = true;
    
    args::Group commands(parser, "commands");
    
    // inject subcommand
    args::Command inject(commands, "inject", "inject library into target process");
    args::ValueFlag<std::string> inject_library(inject, "path", "path to injection library", {'L', "library"});
    args::ValueFlag<std::string> inject_name(inject, "name", "target process name", {'n', "name"});
    args::ValueFlag<int> inject_pid(inject, "pid", "target process id", {'p', "pid"});
    args::ValueFlag<std::string> inject_binary(inject, "path", "binary to launch with injection", {'b', "binary"});
    args::ValueFlag<std::string> inject_tool(inject, "tool", "specify analysis tool (e.g., w1cov)", {'t', "tool"});
    
    // inspect subcommand  
    args::Command inspect(commands, "inspect", "inspect binary file");
    args::ValueFlag<std::string> inspect_binary(inspect, "path", "path to binary file", {'b', "binary"});
    
    // drcov subcommand
    args::Command drcov(commands, "drcov", "analyze DrCov coverage files");
    args::ValueFlag<std::string> drcov_file(drcov, "path", "path to DrCov file", {'f', "file"});
    args::Flag drcov_summary(drcov, "summary", "show summary only", {'s', "summary"});
    args::Flag drcov_detailed(drcov, "detailed", "show detailed basic block listing", {'d', "detailed"});
    args::ValueFlag<std::string> drcov_module(drcov, "module", "filter by module name (substring match)", {'m', "module"});
    
    // global logging options
    args::ValueFlag<std::string> log_level(parser, "level", "log level (critical,error,warn,info,verbose,trace,debug)", {"log-level"});
    args::CounterFlag verbose(parser, "verbose", "increase verbosity: -v=info, -vv=verbose, -vvv=trace, -vvvv=debug", {'v', "verbose"});
    args::Flag quiet(parser, "quiet", "disable colored output", {'q', "quiet"});
    
    args::HelpFlag help(parser, "help", "show help", {'h', "help"});
    
    try {
        parser.ParseCLI(argc, argv);
        
        // apply logging configuration - verbose flags take precedence over log-level
        if (verbose) {
            int verbosity = args::get(verbose);
            if (verbosity == 1) redlog::set_level(redlog::level::info);
            else if (verbosity == 2) redlog::set_level(redlog::level::verbose);
            else if (verbosity == 3) redlog::set_level(redlog::level::trace);
            else if (verbosity >= 4) redlog::set_level(redlog::level::debug);
            
            log.debug("verbosity level set",
                      redlog::field("count", verbosity),
                      redlog::field("level", redlog::level_name(redlog::get_level())));
        } else if (log_level) {
            std::string level_str = args::get(log_level);
            if (level_str == "critical") redlog::set_level(redlog::level::critical);
            else if (level_str == "error") redlog::set_level(redlog::level::error);
            else if (level_str == "warn") redlog::set_level(redlog::level::warn);
            else if (level_str == "info") redlog::set_level(redlog::level::info);
            else if (level_str == "verbose") redlog::set_level(redlog::level::verbose);
            else if (level_str == "trace") redlog::set_level(redlog::level::trace);
            else if (level_str == "debug") redlog::set_level(redlog::level::debug);
            else {
                log.warn("unknown log level, using default", redlog::field("level", level_str));
            }
        }
        
        if (quiet) {
            redlog::set_theme(redlog::themes::plain);
        }
        
        if (inject) {
            return cmd_inject(inject_library, inject_name, inject_pid, inject_binary, inject_tool);
        } else if (inspect) {
            return cmd_inspect(inspect_binary);
        } else if (drcov) {
            return cmd_drcov(drcov_file, drcov_summary, drcov_detailed, drcov_module);
        } else {
            // show help by default when no command specified
            std::cout << parser;
            return 0;
        }
    }
    catch (const args::Help&) {
        std::cout << parser;
        return 0;
    }
    catch (const args::ParseError& e) {
        log.error("command line parse error", redlog::field("error", e.what()));
        std::cout << parser;
        return 1;
    }
    catch (const std::exception& e) {
        log.error("unexpected error", redlog::field("error", e.what()));
        return 1;
    }
    
    return 0;
}