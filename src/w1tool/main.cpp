#include <iostream>
#include <string>
#include "w1tn3ss.hpp"
#include "w1nj3ct.hpp"
#include "ext/args.hpp"

int cmd_inject(args::ValueFlag<std::string>& library_flag, 
               args::ValueFlag<std::string>& name_flag,
               args::ValueFlag<int>& pid_flag,
               args::ValueFlag<std::string>& binary_flag) {
    
    // validate required arguments
    if (!library_flag) {
        w1::util::log_error("library path required");
        return 1;
    }
    
    std::string lib_path = args::get(library_flag);
    w1::inject::result result;
    
    // determine injection method based on arguments
    if (binary_flag) {
        // launch injection
        std::string binary_path = args::get(binary_flag);
        w1::util::log_info("launching " + binary_path + " with library " + lib_path);
        
        result = w1::inject::inject_library_launch(binary_path, lib_path);
        
    } else if (pid_flag) {
        // runtime injection by pid
        int target_pid = args::get(pid_flag);
        w1::util::log_info("injecting " + lib_path + " into pid " + std::to_string(target_pid));
        
        result = w1::inject::inject_library_runtime(lib_path, target_pid);
        
    } else if (name_flag) {
        // runtime injection by process name
        std::string process_name = args::get(name_flag);
        w1::util::log_info("injecting " + lib_path + " into process " + process_name);
        
        result = w1::inject::inject_library_runtime(lib_path, process_name);
        
    } else {
        w1::util::log_error("target required: specify --pid, --name, or --binary");
        return 1;
    }
    
    // handle result
    if (result.success()) {
        if (result.target_pid > 0) {
            w1::util::log_info("injection successful into pid " + std::to_string(result.target_pid));
        } else {
            w1::util::log_info("injection successful");
        }
        return 0;
    } else {
        w1::util::log_error("injection failed: " + result.error_message);
        return 1;
    }
}

int cmd_inspect(args::ValueFlag<std::string>& binary_flag,
                args::Flag& verbose_flag) {
    w1::util::log_info("inspect command called");
    
    // get arguments  
    if (binary_flag) {
        w1::util::log_info("binary path: " + args::get(binary_flag));
    }
    if (verbose_flag) {
        w1::util::log_info("verbose mode enabled");
    }
    w1::util::log_info("todo: implement binary inspection logic");
    
    return 0;
}

int main(int argc, char* argv[]) {
    args::ArgumentParser parser("w1tool - cross-platform dynamic binary analysis tool");
    parser.helpParams.proglineShowFlags = true;
    
    args::Group commands(parser, "commands");
    
    // inject subcommand
    args::Command inject(commands, "inject", "inject library into target process");
    args::ValueFlag<std::string> inject_library(inject, "path", "path to injection library", {'L', "library"});
    args::ValueFlag<std::string> inject_name(inject, "name", "target process name", {'n', "name"});
    args::ValueFlag<int> inject_pid(inject, "pid", "target process id", {'p', "pid"});
    args::ValueFlag<std::string> inject_binary(inject, "path", "binary to launch with injection", {'b', "binary"});
    
    // inspect subcommand  
    args::Command inspect(commands, "inspect", "inspect binary file");
    args::ValueFlag<std::string> inspect_binary(inspect, "path", "path to binary file", {'b', "binary"});
    args::Flag inspect_verbose(inspect, "verbose", "verbose output", {'v', "verbose"});
    
    args::HelpFlag help(parser, "help", "show help", {'h', "help"});
    
    try {
        parser.ParseCLI(argc, argv);
        
        if (inject) {
            return cmd_inject(inject_library, inject_name, inject_pid, inject_binary);
        } else if (inspect) {
            return cmd_inspect(inspect_binary, inspect_verbose);
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
        w1::util::log_error("parse error: " + std::string(e.what()));
        std::cout << parser;
        return 1;
    }
    catch (const std::exception& e) {
        w1::util::log_error("error: " + std::string(e.what()));
        return 1;
    }
    
    return 0;
}