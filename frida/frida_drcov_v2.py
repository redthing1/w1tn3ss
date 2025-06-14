#!/usr/bin/env python

"""
frida_drcov_v2.py
A frida-based tracer that outputs basic block coverage data in the drcov format.

Example usage:

# install frida-tools via uv
uv tool install frida-tools

# run python with uv
uv tool run --from frida-tools python ...

# spawn and trace a binary
python ./tools/frida_drcov_v2.py -S /path/to/binary -o /path/to/coverage.cov
"""

from __future__ import print_function

import argparse
import json
import os
import signal
import sys

import frida

# constants
# drcov basic block entries are 8 bytes:
#   uint32_t start_offset; # offset of bb start from its module's image base
#   uint16_t size;         # size of the basic block
#   uint16_t mod_id;       # id of the module containing the bb
DRCOV_BB_ENTRY_SIZE_BYTES = 8

# script description
# this script implements a frida-based tracer that outputs basic block (bb)
# coverage data in the drcov format. this format is commonly used by tools
# like dynamorio and can be consumed by visualizers like lighthouse.
#
# javascript (frida agent) responsibilities:
#   - enumerate process modules at script start and send their information (name, base,
#     size, path) to the python host. this data is augmented with a unique id
#     and calculated end address for each module.
#   - use frida's stalker to trace thread execution. stalker instruments code by
#     compiling basic blocks and allows capturing 'compile' events for these blocks.
#   - leverage process.attachthreadobserver to dynamically apply stalking to both
#     threads existing at script start and any threads created during runtime.
#   - parse raw stalker 'compile' events, which yield [start_address, end_address]
#     pairs for each instrumented basic block.
#   - convert these bb address pairs into the compact drcov binary format:
#     - calculate the bb start offset relative to its module's base address.
#     - determine the bb size from the start and end addresses.
#     - look up the pre-assigned module id.
#   - send batches of these drcov-formatted bb entries (as byte arrays) to the
#     python host for aggregation and file writing.
#
# python (host) responsibilities:
#   - parse command-line arguments: target process (pid/name for attach, or
#     program path for spawn), output file name, module/thread whitelists,
#     and device/host selection.
#   - manage the frida session:
#     - if spawning: start the target executable, attach to the new pid, load the
#       js agent, and then resume the process.
#     - if attaching: connect to the existing process pid/name and load the js agent.
#   - handle communication with the js agent:
#     - receive the initial module map.
#     - receive batches of drcov-formatted basic block data.
#   - store collected module information in a list of dictionaries.
#   - store unique drcov bb entries in a python set to automatically handle
#     deduplication (as the same bb might be reported multiple times, e.g., if
#     executed by different threads or re-instrumented by stalker).
#   - upon termination (e.g., ctrl+c or normal exit after stdin.read()), format
#     the collected module information and bb entries into the drcov logfile format:
#     a header with a module table, followed by a bb table and the binary bb entries.
#   - write the complete drcov log file to disk.

# frida javascript agent code
# this script is injected into the target process.
# it is dynamically formatted by python to include:
# 1. whitelisted_modules_json: a json string array of module names to trace (e.g., "['main_exe', 'important.dll']").
#    if "['all']", all modules are considered for tracing.
# 2. thread_list_json: a json string array of os-specific thread ids (numbers) to trace (e.g., "[123, 456]").
#    if "['all']", all threads are stalked.
js_agent_code = """
"use strict";

// dynamically configured by python host through string formatting
var whitelistedModules = %s; // e.g., ['module_a.so', 'all']
var threadIdList = %s;     // e.g., [123, 456, 'all'] (parsed into numbers or ['all'] by python)

// drcov basic block entries are 8 bytes:
//   uint32_t start_offset; (from module base)
//   uint16_t size;
//   uint16_t mod_id;
const DRCOV_BB_ENTRY_SIZE_BYTES = 8;

// prepares module data. creates two versions:
// 1. internal_use_modules: for javascript logic, keeps base/end addresses as nativepointer objects
//    for efficient arithmetic and lookups.
// 2. python_send_modules: for sending to the python host, converts base/end addresses to strings
//    (as nativepointer objects don't serialize well over frida's send mechanism for this purpose)
//    and explicitly includes 'id' and 'end' properties.
function prepareModuleData() {
    var rawModules = Process.enumerateModules(); // gets currently loaded modules
    var internalUseModules = [];
    var pythonSendModules = [];

    for (var i = 0; i < rawModules.length; i++) {
        var mod = rawModules[i];
        var moduleEndAddress = mod.base.add(mod.size); // calculate end address (nativepointer)

        // version for internal js use
        internalUseModules.push({
            id: i, // assign a simple integer id
            name: mod.name,
            base: mod.base, // nativepointer
            size: mod.size,
            path: mod.path,
            end: moduleEndAddress // nativepointer
        });

        // version for sending to python
        pythonSendModules.push({
            id: i,
            name: mod.name,
            base: mod.base.toString(), // stringified for python
            size: mod.size,
            path: mod.path,
            end: moduleEndAddress.toString() // stringified for python
        });
    }
    return { internal: internalUseModules, forPython: pythonSendModules };
}

// - initial module processing
var moduleProcessingResult = prepareModuleData();
var modulesForJsLogic = moduleProcessingResult.internal;    // for js-side logic
var modulesForPythonHost = moduleProcessingResult.forPython; // for python host

// send the python-friendly module list to the host immediately upon script load
send({'map': modulesForPythonHost});

// create a lookup table: module_path -> {id: module_id, start: module_base_nativepointer}
// this map is used by `convertBasicBlocksToDrcov` to quickly find module information
// (id and nativepointer base address) for a given basic block's module path.
var modulePathToIdMap = {};
modulesForJsLogic.forEach(function (moduleEntry) {
    modulePathToIdMap[moduleEntry.path] = {id: moduleEntry.id, start: moduleEntry.base};
});

// frida's modulemap is an efficient way to determine which module an address belongs to.
// it's initialized with a snapshot of modules. the filter function determines which modules
// are included in this map, based on the `whitelistedModules` list.
// note: this map is created once. if modules are loaded/unloaded dynamically *during*
// tracing, this map would need to be updated (e.g. via moduleobserver and map.update())
// for those changes to be reflected in `filteredModuleMap.findPath()`.
// current script relies on the initial module snapshot.
var filteredModuleMap = new ModuleMap(function (m) { // m is a frida module object
    if (whitelistedModules.indexOf('all') >= 0) {
        return true; // if 'all' is whitelisted, include all modules
    }
    // otherwise, check if the module's name (case-insensitive) is included in any whitelist item
    return whitelistedModules.some(item => m.name.toLowerCase().includes(item.toLowerCase()));
});

// converts a list of stalker's basic block 'compile' events into drcov formatted entries.
//   basicBlockEvents: array of [startAddressNativePointer, endAddressNativePointer] from stalker.parse().
//   activeModuleMap: the `filteredModuleMap` for resolving an address to a module path.
//   pathToIdLookup: the `modulePathToIdMap` for getting module id and base address from path.
function convertBasicBlocksToDrcov(basicBlockEvents, activeModuleMap, pathToIdLookup) {
    // pre-allocate buffer for all potential entries for efficiency
    var buffer = new ArrayBuffer(DRCOV_BB_ENTRY_SIZE_BYTES * basicBlockEvents.length);
    var numEntriesWritten = 0;

    for (var i = 0; i < basicBlockEvents.length; ++i) {
        var blockEvent = basicBlockEvents[i]; // [startAddress, endAddress]
        var startAddress = blockEvent[0];     // nativepointer
        var endAddress = blockEvent[1];       // nativepointer

        // find the path of the module containing the start address of the basic block.
        // this uses the `filteredModuleMap`, so only whitelisted modules are considered.
        var modulePath = activeModuleMap.findPath(startAddress);
        if (modulePath === null) {
            // address does not map to any known (and whitelisted) module; skip this bb
            continue;
        }

        var moduleInfo = pathToIdLookup[modulePath];
        // ensure moduleinfo exists and its 'start' is a nativepointer (it should be by design)
        if (!moduleInfo || !(moduleInfo.start instanceof NativePointer)) {
            // this case should ideally not happen if modulepath was resolved correctly
            // console.warn("module info issue for path: " + modulePath);
            continue;
        }

        // calculate drcov fields:
        var offset = startAddress.sub(moduleInfo.start).toInt32(); // bb offset from module base
        var size = endAddress.sub(startAddress).toInt32();         // bb size
        var moduleId = moduleInfo.id;                              // pre-assigned module id

        // write data to the arraybuffer using typedarray views.
        // this assumes the host platform's endianness matches drcov's expectation (little-endian).
        // this is generally true for common frida targets (x86, arm in le mode).
        var currentOffsetBytes = numEntriesWritten * DRCOV_BB_ENTRY_SIZE_BYTES;

        // write offset (uint32_t)
        new Uint32Array(buffer, currentOffsetBytes, 1)[0] = offset;
        // write size (uint16_t) and mod_id (uint16_t)
        // create a new view for each entry to ensure correct offset for the 16-bit values
        var uint16View = new Uint16Array(buffer, currentOffsetBytes + 4, 2);
        uint16View[0] = size;
        uint16View[1] = moduleId;

        ++numEntriesWritten;
    }

    if (numEntriesWritten === 0) {
        return null; // no valid bbs were processed from this batch
    }
    // return only the populated part of the buffer as a uint8array
    return new Uint8Array(buffer, 0, numEntriesWritten * DRCOV_BB_ENTRY_SIZE_BYTES);
}

// - stalker configuration
// trustthreshold = 0: disables frida's self-healing mechanism for jitted code (assumes no smc).
// can improve performance if self-modifying code is not a concern or not supported by analysis.
Stalker.trustThreshold = 0;

// helper function to initiate stalking on a thread if it matches the filter criteria.
function startStalkingThreadIfNeeded(threadId) { // threadid is the os-specific id (number)
    // check if this thread should be stalked based on `threadIdList`
    var shouldStalkThisThread = threadIdList.indexOf('all') >= 0 || threadIdList.indexOf(threadId) >= 0;

    if (!shouldStalkThisThread) {
        // console.log('thread ' + threadId + ' does not match filter, not stalking.');
        return;
    }

    console.log('stalking thread ' + threadId + '.');

    Stalker.follow(threadId, {
        events: {
            compile: true // we are interested in 'compile' events. these occur when stalker
                          // instruments a new basic block, providing its start and end addresses.
        },
        onReceive: function (rawStalkerEvents) {
            // rawstalkerevents is the raw data buffer from stalker.
            // stalker.parse converts this into a more usable format.
            // with stringify:false, annotate:false, it returns an array of [begin_addr, end_addr] pairs.
            var parsedBasicBlocks = Stalker.parse(rawStalkerEvents, {stringify: false, annotate: false});

            if (parsedBasicBlocks && parsedBasicBlocks.length > 0) {
                var drcovFormattedBlocks = convertBasicBlocksToDrcov(parsedBasicBlocks, filteredModuleMap, modulePathToIdMap);
                if (drcovFormattedBlocks && drcovFormattedBlocks.buffer.byteLength > 0) {
                    // send the drcov data (as a byte array) to the python host.
                    // the first argument to send() is a json serializable message.
                    // the second (optional) argument is raw binary data (arraybuffer or uint8array).
                    send({bbs: 1}, drcovFormattedBlocks); // {bbs:1} is a simple marker payload
                }
            }
        }
    });
}

// - main stalking logic setup
// use process.attachthreadobserver to handle both existing and newly created threads.
// the 'onadded' callback is invoked for all existing threads immediately upon registration,
// and then subsequently for any new threads as they are created by the process.
var threadObserver = Process.attachThreadObserver({
    onAdded: function (thread) { // `thread` is a frida thread object
        // `thread.id` is the os-specific id, which is what stalker.follow expects.
        // console.log('thread observer: onadded - thread.id: ' + thread.id + ', state: ' + thread.state);
        startStalkingThreadIfNeeded(thread.id);
    },
    onRemoved: function (thread) {
        // console.log('thread observer: onremoved - thread.id: ' + thread.id);
        // note: explicit stalker.unfollow(thread.id) here could be problematic if the
        // thread is already gone or if stalker is in a sensitive state during thread exit.
        // frida typically handles cleanup of stalker resources associated with
        // a thread when the thread exits or the script is unloaded.
        // if specific per-thread cleanup for stalker is needed, it requires careful handling.
    }
});
// the threadobserver itself is managed by frida's script lifecycle.
// calling threadobserver.detach() would stop observing.
console.log('thread observer attached. stalking initial and any future threads matching criteria.');
"""

# global variables for storing collected data from the frida agent
collected_modules = []  # list of module dictionaries
collected_bbs_drcov = set([])  # set of unique drcov basic block entries (bytes)
output_log_file = "frida-cov.log"  # default output file name


def _populate_modules_global(module_list_from_js):
    """
    processes the module list received from javascript and populates `collected_modules`.
    converts stringified addresses from js to integers for python-side use.
    """
    global collected_modules
    collected_modules = []  # clear any previous module data
    for module_info_js in module_list_from_js:
        try:
            module_id = module_info_js["id"]
            module_path = module_info_js["path"]
            # addresses are sent as strings from js, convert to int
            base_address = int(
                str(module_info_js["base"]), 0
            )  # base 0 for auto-detect hex/dec
            end_address = int(str(module_info_js["end"]), 0)
            module_size = int(
                module_info_js["size"]
            )  # size is typically already a number
            module_name = module_info_js["name"]

            module_dict = {
                "id": module_id,
                "path": module_path,
                "base": base_address,
                "end": end_address,
                "size": module_size,
                "name": module_name,
            }
            collected_modules.append(module_dict)
        except KeyError as e:
            print(
                f"[-] error processing module (KeyError: {e}): {module_info_js}. "
                "mismatch in expected fields from javascript agent."
            )
            continue
        except (
            Exception
        ) as e:  # catch other potential errors like ValueError from int()
            print(f"[-] error processing module data: {module_info_js}. error: {e}")
            continue
    # sort modules by id for consistent output in the drcov file module table
    collected_modules.sort(key=lambda m: m["id"])
    print(f"[+] processed module info for {len(collected_modules)} modules.")


def _populate_bbs_global(bb_data_buffer):
    """
    processes a raw byte buffer of drcov bb entries received from javascript.
    each entry is 8 bytes. adds unique entries to the global `collected_bbs_drcov` set.
    """
    global collected_bbs_drcov
    if bb_data_buffer is None or len(bb_data_buffer) == 0:
        return  # no data to process

    # ensure received data length is a multiple of the bb entry size
    if len(bb_data_buffer) % DRCOV_BB_ENTRY_SIZE_BYTES != 0:
        print(
            f"[-] warning: received bb data of length {len(bb_data_buffer)}, "
            f"which is not a multiple of entry size {DRCOV_BB_ENTRY_SIZE_BYTES}. skipping this batch."
        )
        return

    # iterate through the buffer, extracting each 8-byte entry
    # the set automatically handles deduplication.
    for i in range(0, len(bb_data_buffer), DRCOV_BB_ENTRY_SIZE_BYTES):
        bb_entry_bytes = bb_data_buffer[i : i + DRCOV_BB_ENTRY_SIZE_BYTES]
        collected_bbs_drcov.add(bb_entry_bytes)


def _create_drcov_header(module_list):
    """
    creates the drcov log file header string, including the module table.
    the header provides metadata about the coverage data and lists loaded modules.
    """
    header_lines = []
    header_lines.append("DRCOV VERSION: 2")
    header_lines.append("DRCOV FLAVOR: frida")  # custom flavor identifier

    if not module_list:
        print(
            "[-] warning: no modules found to include in drcov header. module table will be empty."
        )
        header_lines.append("Module Table: version 2, count 0")
    else:
        header_lines.append(f"Module Table: version 2, count {len(module_list)}")

    # drcov module table columns: id, base, end, entry, checksum, timestamp, path
    # frida does not readily provide 'entry' (actual entry point beyond base),
    # 'checksum', or 'timestamp' for modules in a cross-platform way.
    # these are often zeroed out or use base for entry in drcov logs from similar tools.
    header_lines.append("Columns: id, base, end, entry, checksum, timestamp, path")

    for m_data in module_list:
        # format: "%3d, %#016x, %#016x, %#016x, %#08x, %#08x, %s"
        # using 0 for entry (can also be m_data["base"]), checksum, timestamp
        entry_line = "%3d, %#016x, %#016x, %#016x, %#08x, %#08x, %s" % (
            m_data["id"],
            m_data["base"],
            m_data["end"],
            0,  # entry point (placeholder, could use m_data["base"])
            0,  # checksum (placeholder)
            0,  # timestamp (placeholder)
            m_data["path"],
        )
        header_lines.append(entry_line)

    return ("\n".join(header_lines) + "\n").encode(
        "utf-8"
    )  # ensure newline at end of header section


def _create_drcov_body(bb_set):
    """
    creates the drcov log file body. this consists of the "bb table" line
    indicating the number of unique basic blocks, followed by the concatenation
    of all unique, sorted bb entries (each 8 bytes).
    bbs are sorted for deterministic output, aiding in comparisons of log files.
    """
    # sort bbs for deterministic output (lexicographical sort of the byte strings)
    sorted_bbs = sorted(list(bb_set))
    bb_table_header = f"BB Table: {len(sorted_bbs)} bbs\n".encode("utf-8")
    # concatenate all binary bb entries
    return bb_table_header + b"".join(sorted_bbs)


def _on_frida_message(message, binary_data):
    """
    callback function invoked when a message is received from the frida javascript agent.
    handles 'error' messages and 'send' messages containing module maps or bb data.
    """
    if message["type"] == "error":
        print(
            f"[!] frida script error: {message.get('description', 'no description available')}"
        )
        if "stack" in message:
            print(message["stack"])
        # consider if script should terminate on js error, or attempt to continue
        return

    if message["type"] == "send":
        payload = message.get(
            "payload", {}
        )  # use .get for safety if payload might be missing
        if "map" in payload:  # message contains module information
            module_map_data = payload["map"]
            _populate_modules_global(
                module_map_data or []
            )  # handle if map is null/empty
        elif (
            "bbs" in payload
        ):  # message indicates accompanying binary_data contains bbs
            if binary_data:  # ensure binary_data is not none
                _populate_bbs_global(binary_data)
            # else:
            # print("[-] received bbs signal from js but no accompanying binary data.")
        # else:
        # print(f"[-] unknown payload type in 'send' message from js: {payload}")


def _signal_handler_save_exit(signal_number, _):  # current_stack_frame is unused
    """
    signal handler for sigint (ctrl+c) and sigterm.
    triggers saving of coverage data and then exits the script.
    """
    print(f"\n[!] received signal {signal_number}, preparing to save coverage data...")
    _save_coverage_to_file()
    print(f"[!] coverage data saved. exiting due to signal {signal_number}.")
    os._exit(
        1
    )  # use os._exit for immediate termination in signal handlers to avoid issues


def _save_coverage_to_file():
    """
    formats the collected module and bb data and writes it to the output drcov log file.
    this function is called on normal termination or by the signal handler.
    """
    global collected_modules, collected_bbs_drcov, output_log_file
    if not collected_modules:
        print(
            "[-] warning: no module information was collected. "
            "the output drcov file might be incomplete or invalid for some analysis tools."
        )
    if not collected_bbs_drcov:
        print(
            "[-] warning: no basic blocks were collected. the coverage log will not contain bb entries."
        )

    print(
        f"[*] saving {len(collected_bbs_drcov)} unique basic blocks to '{output_log_file}'..."
    )

    try:
        drcov_header_bytes = _create_drcov_header(collected_modules)
        drcov_body_bytes = _create_drcov_body(collected_bbs_drcov)

        with open(output_log_file, "wb") as f_out:  # open in binary write mode
            f_out.write(drcov_header_bytes)
            f_out.write(drcov_body_bytes)
        print(f"[+] coverage data successfully written to {output_log_file}.")
    except IOError as e:
        print(f"[!] IOError saving coverage data to '{output_log_file}': {e}")
    except Exception as e:
        print(f"[!] an unexpected error occurred while saving coverage data: {e}")


def main():
    global output_log_file  # allow main to modify the global output_log_file name

    parser = argparse.ArgumentParser(
        description="frida-based basic block tracer, outputs in drcov format.",
        formatter_class=argparse.RawTextHelpFormatter,  # allows for better formatting of help text
    )
    parser.add_argument(
        "target_process_specifier",
        help="target to trace.\n"
        "  for attaching: process id (pid) or process name.\n"
        "  for spawning: full path to the executable.",
    )
    parser.add_argument(
        "-S",
        "--spawn",
        action="store_true",
        help="spawn the target executable instead of attaching. "
        "'target_process_specifier' must be the program path.",
    )
    parser.add_argument(
        "-o",
        "--outfile",
        help="output coverage file name (default: frida-cov.log)",
        default="frida-cov.log",
    )
    parser.add_argument(
        "-w",
        "--whitelist-modules",
        action="append",
        default=[],
        help="module name (or part of it, case-insensitive) to trace.\n"
        "can be specified multiple times (e.g., -w main.exe -w helper.dll).\n"
        "default: trace all modules (equivalent to -w all).",
    )
    parser.add_argument(
        "-t",
        "--thread-id",
        action="append",
        default=[],
        help="os-specific thread id to trace. can be specified multiple times (e.g., -t 123 -t 456).\n"
        "default: trace all threads (equivalent to -t all).",
    )
    parser.add_argument(
        "-D",
        "--device",
        default="local",
        help="select frida device by id (e.g., 'usb', 'local', 'remote'). default: 'local'",
    )
    parser.add_argument(
        "-H",
        "--host",
        default=None,
        help="connect to remote frida-server on host:port (e.g., '192.168.1.100:27042')",
    )

    parsed_args = parser.parse_args()
    output_log_file = parsed_args.outfile  # set global based on arg or default

    # initialize frida-related objects for the finally block
    frida_device = None
    frida_session = None
    loaded_frida_script = None
    resolved_target_pid = -1  # used for logging in case of errors

    try:
        # - frida device selection
        if parsed_args.host:
            # connect to a remote frida-server
            device_manager = frida.get_device_manager()
            frida_device = device_manager.add_remote_device(parsed_args.host)
            print(
                f"[*] attempting to use remote frida device: {frida_device.id} at {parsed_args.host}"
            )
        else:
            # use a local or specified frida device (e.g., usb)
            frida_device = frida.get_device(parsed_args.device)
            print(
                f"[*] using frida device: {frida_device.id} (name: {frida_device.name}, type: {frida_device.type})"
            )

        # - target process identification & session setup
        if parsed_args.spawn:
            target_path = parsed_args.target_process_specifier
            print(
                f"[*] attempting to spawn executable: '{target_path}' on device '{frida_device.id}'..."
            )
            try:
                # device.spawn() starts the process paused, returning its pid
                resolved_target_pid = frida_device.spawn([target_path])
                print(
                    f"[+] successfully spawned '{target_path}' with pid {resolved_target_pid}. process is initially paused."
                )
            except frida.ExecutableNotFoundError:
                print(
                    f"[-] error: executable not found at path '{target_path}' on device '{frida_device.id}'."
                )
                sys.exit(1)
            except (
                frida.FridaError
            ) as e:  # catch other frida-specific errors during spawn
                print(f"[-] frida.FridaError spawning '{target_path}': {e}")
                sys.exit(1)

            # attach to the newly spawned (and paused) process to inject the script
            print(
                f"[*] attaching to spawned pid '{resolved_target_pid}' to load agent script..."
            )
            frida_session = frida_device.attach(resolved_target_pid)
        else:  # attach mode to an existing process
            # try to interpret target as a pid first
            try:
                resolved_target_pid = int(parsed_args.target_process_specifier)
                print(f"[*] target specified as pid: {resolved_target_pid}")
            except ValueError:
                # if not an integer, assume it's a process name
                process_name_to_find = parsed_args.target_process_specifier
                print(
                    f"[*] target specified as name: '{process_name_to_find}'. searching for pid..."
                )
                try:
                    # attempt to get process by name directly (more efficient if name is unique)
                    resolved_target_pid = frida_device.get_process(
                        process_name_to_find
                    ).pid
                    print(
                        f"[*] found process '{process_name_to_find}' with pid {resolved_target_pid} by direct lookup."
                    )
                except frida.ProcessNotFoundError:
                    # if direct lookup fails, enumerate all processes and match name/pid
                    print(
                        f"[-] process '{process_name_to_find}' not found by direct lookup. enumerating all processes..."
                    )
                    matching_processes = [
                        p
                        for p in frida_device.enumerate_processes()
                        if process_name_to_find == p.name
                        or process_name_to_find == str(p.pid)
                    ]
                    if not matching_processes:
                        print(
                            f"[-] error: could not find any running process matching '{process_name_to_find}' on device '{frida_device.id}'."
                        )
                        sys.exit(1)
                    elif len(matching_processes) > 1:
                        print(
                            f"[-] warning: multiple processes match '{process_name_to_find}':"
                        )
                        for p_info in matching_processes:
                            print(f"    pid: {p_info.pid}, name: {p_info.name}")
                        resolved_target_pid = matching_processes[
                            0
                        ].pid  # default to the first match
                        print(
                            f"    using pid: {resolved_target_pid} (the first one found). be more specific if this is not the intended target."
                        )
                    else:  # exactly one match from enumeration
                        resolved_target_pid = matching_processes[0].pid
                        print(
                            f"[*] found process '{matching_processes[0].name}' with pid {resolved_target_pid} via enumeration."
                        )

            if (
                resolved_target_pid == -1
            ):  # should be caught by earlier checks, but as a safeguard
                print(
                    f"[-] error: could not determine pid for attach target '{parsed_args.target_process_specifier}'."
                )
                sys.exit(1)

            print(
                f"[*] attaching to existing process with pid '{resolved_target_pid}'..."
            )
            frida_session = frida_device.attach(resolved_target_pid)

        # - setup signal handlers for graceful shutdown (ctrl+c, kill)
        signal.signal(signal.SIGINT, _signal_handler_save_exit)
        signal.signal(signal.SIGTERM, _signal_handler_save_exit)

        # - prepare whitelists for javascript agent
        # module whitelist: use provided list or default to ['all'] if empty
        js_whitelisted_modules = parsed_args.whitelist_modules or ["all"]

        # thread id list: process into numbers or ['all'] for js
        raw_js_thread_list_input = parsed_args.thread_id or ["all"]

        processed_js_thread_list = []
        if "all" in raw_js_thread_list_input:
            processed_js_thread_list = ["all"]  # 'all' takes precedence
        else:
            for item in raw_js_thread_list_input:
                try:
                    processed_js_thread_list.append(int(item))
                except ValueError:
                    print(
                        f"[-] warning: invalid thread id '{item}' in list, ignored. please provide numbers or 'all'."
                    )
            if (
                not processed_js_thread_list
            ):  # if all items were invalid and 'all' wasn't specified
                print(
                    "[-] no valid thread ids provided and 'all' not specified. defaulting to tracing 'all' threads."
                )
                processed_js_thread_list = ["all"]

        # - load and run frida script in the target process
        print(
            f"[+] session established with pid {resolved_target_pid}. loading agent script..."
        )
        # format the javascript agent code with the dynamic whitelist/threadlist values
        frida_script_source = js_agent_code % (
            json.dumps(js_whitelisted_modules),
            json.dumps(processed_js_thread_list),
        )

        loaded_frida_script = frida_session.create_script(frida_script_source)
        loaded_frida_script.on(
            "message", _on_frida_message
        )  # register message handler callback
        loaded_frida_script.load()  # inject and execute the script in the target
        print("[+] agent script loaded into target process.")

        # - resume spawned process (if applicable) *after* script is loaded and ready
        if parsed_args.spawn:
            print(
                f"[*] resuming spawned process pid {resolved_target_pid} to begin execution..."
            )
            frida_device.resume(resolved_target_pid)
            print("[+] spawned process resumed.")

        print(
            "[*] now collecting coverage info. press ctrl+c to terminate and save results."
        )
        # keep the python script alive to receive messages from frida.
        # sys.stdin.read() waits for eof (e.g., ctrl+d in terminal), or until interrupted by a signal.
        sys.stdin.read()

    except frida.TransportError as e:
        print(
            f"[!] frida.TransportError: {e}. ensure frida-server is running on the target and accessible."
        )
        print(
            "    details: if using usb, check 'frida-ps -ua'. if network, check host/port and firewall."
        )
    except frida.InvalidOperationError as e:
        print(
            f"[!] frida.InvalidOperationError: {e}. this might occur if the process terminated unexpectedly, "
            "or if there's an issue with instrumentation (e.g., stalker compatibility)."
        )
    except frida.ProcessNotFoundError:
        pid_for_error_msg = (
            resolved_target_pid
            if resolved_target_pid != -1
            else parsed_args.target_process_specifier
        )
        print(
            f"[-] error: process {pid_for_error_msg} not found or terminated during operation."
        )
    except (
        KeyboardInterrupt
    ):  # handles ctrl+c if pressed before signal handler is fully effective or during stdin.read
        print(
            "\n[*] KeyboardInterrupt detected. initiating shutdown and saving coverage..."
        )
        # signal handler should ideally take over, but this ensures save is attempted.
    except Exception as e:
        print(f"[!] an unexpected error occurred in the main execution block: {e}")
        import traceback

        traceback.print_exc()
    finally:
        print("[*] script terminating. performing cleanup...")
        # attempt to unload script and detach session gracefully
        if loaded_frida_script and not loaded_frida_script.is_destroyed:
            try:
                print("[*] unloading frida agent script from target...")
                loaded_frida_script.unload()
            except Exception as e_unload:
                print(
                    f"[!] warning: error unloading frida script (process might have already exited): {e_unload}"
                )
        if frida_session:
            try:
                print("[*] detaching frida session from target...")
                frida_session.detach()
                print("[+] frida session detached successfully.")
            except Exception as e_detach:
                print(
                    f"[!] warning: error detaching frida session (process might have already exited): {e_detach}"
                )

        # always attempt to save coverage data, regardless of prior errors
        _save_coverage_to_file()
        print("[!] frida drcov script finished.")
        # python will exit naturally here unless os._exit was called by the signal handler


if __name__ == "__main__":
    main()
