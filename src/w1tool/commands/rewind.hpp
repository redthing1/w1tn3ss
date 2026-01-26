#pragma once

#include "w1base/ext/args.hpp"
#include <cstdint>

namespace w1tool::commands {

/**
 * rewind command - records rewind traces with convenient options
 *
 * @param library_flag path to w1rewind library (auto-detected if not specified)
 * @param spawn_flag spawn new process for tracing
 * @param pid_flag process id to attach to for runtime tracing
 * @param name_flag process name to attach to for runtime tracing
 * @param output_flag output file path for trace data (optional)
 * @param flow_flag flow mode (block, instruction) (optional)
 * @param reg_deltas_flag enable register delta capture (optional)
 * @param reg_snapshot_interval_flag register snapshot interval (optional)
 * @param stack_window_mode_flag stack window mode (none, fixed, frame) (optional)
 * @param stack_above_flag stack window bytes above SP (optional)
 * @param stack_below_flag stack window bytes below SP (optional)
 * @param stack_max_flag stack window max bytes (optional)
 * @param stack_snapshot_interval_flag stack snapshot interval (optional)
 * @param mem_access_flag memory access capture (none, reads, writes, reads_writes) (optional)
 * @param mem_values_flag capture memory values (optional)
 * @param mem_max_bytes_flag max bytes per memory value (optional)
 * @param mem_filter_flag memory filter list (all, ranges, stack_window) (optional)
 * @param mem_ranges_flag memory ranges start-end (optional)
 * @param module_filter_flag comma-separated list of modules to filter (optional)
 * @param system_policy_flag system module policy (exclude_all, include_critical, include_all) (optional)
 * @param threads_flag thread attach policy (main, auto) (optional)
 * @param compress_flag enable zstd compression (default on if available)
 * @param chunk_size_flag trace chunk size (optional)
 * @param config_flags configuration key=value pairs (optional)
 * @param debug_level_flag debug level override - defaults to passthrough verbosity (optional)
 * @param suspended_flag start process in suspended state (optional)
 * @param no_aslr_flag disable ASLR when launching process (optional)
 * @param args_list binary and arguments (use -- to separate w1tool args from target args)
 * @param executable_path path to the current executable (for auto-discovery)
 * @return exit code (0 for success, 1 for failure)
 */
int rewind(
    args::ValueFlag<std::string>& library_flag, args::Flag& spawn_flag, args::ValueFlag<int>& pid_flag,
    args::ValueFlag<std::string>& name_flag, args::ValueFlag<std::string>& output_flag,
    args::ValueFlag<std::string>& flow_flag, args::Flag& reg_deltas_flag,
    args::ValueFlag<uint64_t>& reg_snapshot_interval_flag, args::ValueFlag<std::string>& stack_window_mode_flag,
    args::ValueFlag<uint64_t>& stack_above_flag, args::ValueFlag<uint64_t>& stack_below_flag,
    args::ValueFlag<uint64_t>& stack_max_flag, args::ValueFlag<uint64_t>& stack_snapshot_interval_flag,
    args::ValueFlag<std::string>& mem_access_flag, args::Flag& mem_values_flag,
    args::ValueFlag<uint32_t>& mem_max_bytes_flag, args::ValueFlagList<std::string>& mem_filter_flag,
    args::ValueFlagList<std::string>& mem_ranges_flag, args::ValueFlag<std::string>& module_filter_flag,
    args::ValueFlag<std::string>& system_policy_flag, args::ValueFlag<std::string>& threads_flag,
    args::Flag& compress_flag, args::ValueFlag<uint32_t>& chunk_size_flag,
    args::ValueFlagList<std::string>& config_flags, args::ValueFlag<int>& debug_level_flag,
    args::Flag& suspended_flag, args::Flag& no_aslr_flag, args::PositionalList<std::string>& args_list,
    const std::string& executable_path
);

} // namespace w1tool::commands
