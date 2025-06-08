#include <iostream>
#include <string>
#include "w1tn3ss.hpp"
#include "ext/args.hpp"

int cmd_inject(args::ValueFlag<std::string>& library_flag, 
               args::ValueFlag<std::string>& name_flag,
               args::ValueFlag<int>& pid_flag) {
    w1::util::log_info("inject command called");
    
    // get arguments
    if (library_flag) {
        w1::util::log_info("library path: " + args::get(library_flag));
    }
    if (name_flag) {
        w1::util::log_info("process name: " + args::get(name_flag));
    }
    if (pid_flag) {
        w1::util::log_info("process pid: " + std::to_string(args::get(pid_flag)));
    }
    w1::util::log_info("todo: implement injection logic");
    
    return 0;
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
    args::Command inject(commands, "inject", "inject w1tn3ss library into target process");
    args::ValueFlag<std::string> inject_library(inject, "path", "path to w1tn3ss library", {'L', "library"});
    args::ValueFlag<std::string> inject_name(inject, "name", "target process name", {'n', "name"});
    args::ValueFlag<int> inject_pid(inject, "pid", "target process id", {'p', "pid"});
    
    // inspect subcommand  
    args::Command inspect(commands, "inspect", "inspect binary file");
    args::ValueFlag<std::string> inspect_binary(inspect, "path", "path to binary file", {'b', "binary"});
    args::Flag inspect_verbose(inspect, "verbose", "verbose output", {'v', "verbose"});
    
    args::HelpFlag help(parser, "help", "show help", {'h', "help"});
    
    try {
        parser.ParseCLI(argc, argv);
        
        if (inject) {
            return cmd_inject(inject_library, inject_name, inject_pid);
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