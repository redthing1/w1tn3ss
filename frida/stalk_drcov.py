#!/usr/bin/env python3

"""
stalk_drcov.py
A frida-based basic block tracer that outputs coverage data in the drcov format.

Example usage:

# install frida-tools via uv
uv tool install frida-tools

# run python with uv
uv tool run --from frida-tools python ...

# spawn and trace a binary
python stalk_drcov.py -s /path/to/binary -o coverage.drcov

# attach to existing process by PID
python stalk_drcov.py 1234 -o coverage.drcov

# attach to process by name
python stalk_drcov.py myapp -o coverage.drcov

# trace specific modules only
python stalk_drcov.py 1234 -w main.exe -w helper.dll -o coverage.drcov

# trace all modules excluding system modules
python stalk_drcov.py -s ./target --no-system -o coverage.drcov

# disable ASLR for spawned process (macOS only)
python stalk_drcov.py -s ./target --disable-aslr -o coverage.drcov

# spawn with arguments (use -- to separate)
python stalk_drcov.py -s ./target --no-system -- --input file.txt --verbose

# enable hit count tracking (uses block events)
python stalk_drcov.py -s ./target --hits -o coverage-with-hits.drcov
"""

from __future__ import print_function

import argparse
import json
import os
import signal
import struct
import sys
import time
from typing import List, Dict, Set, Optional

import frida

# constants
VERSION = "1.0.0"
DRCOV_BB_ENTRY_SIZE_BYTES = 8

# javascript agent code for basic block tracing
js_agent_code = """
"use strict";

// configuration passed from python
const config = JSON.parse('CONFIG_JSON_PLACEHOLDER');
const whitelistedModules = config.whitelistedModules || ['all'];
const threadIdList = config.threadIdList || ['all'];
const excludeSystem = config.excludeSystem || false;
const useHitCounting = config.useHitCounting || false;
const verbose = config.verbose || false;

// drcov basic block entries are 8 bytes:
//   uint32_t start_offset; (from module base)
//   uint16_t size;
//   uint16_t mod_id;
const DRCOV_BB_ENTRY_SIZE_BYTES = 8;

// system module detection
function isSystemModule(moduleName, modulePath) {
    const name = moduleName.toLowerCase();
    const path = modulePath ? modulePath.toLowerCase() : '';
    
    // Cross-platform system module patterns
    const systemPatterns = [
        // macOS system modules
        /^lib(system|c|objc|dispatch|foundation|corefoundation|security)/,
        /^(dyld|libdyld)/,
        /\\.framework\\//,
        /^\\/system\\//,
        /^\\/usr\\/lib\\//,
        
        // Linux system modules
        /^lib(c|pthread|dl|m|rt|resolv|nsl|util|crypt)\\.so/,
        /^ld-linux/,
        /^\\/lib\\//,
        /^\\/usr\\/lib\\//,
        /^linux-vdso/,
        
        // Windows system modules  
        /^(ntdll|kernel32|user32|advapi32|ole32|oleaut32|shell32|gdi32|winmm|ws2_32|crypt32|rpcrt4|comctl32|comdlg32|version|shlwapi)\\.dll$/,
        /^msvcrt/,
        /^ucrtbase/,
        /^vcruntime/,
        /^api-ms-/,
        /^ext-ms-/,
        
        // Common patterns
        /^libc\\+\\+/,
        /^libstdc\\+\\+/,
        /^libgcc/
    ];
    
    return systemPatterns.some(pattern => 
        pattern.test(name) || (path && pattern.test(path))
    );
}

// prepare module data
function prepareModuleData() {
    var rawModules = Process.enumerateModules();
    var internalUseModules = [];
    var pythonSendModules = [];

    for (var i = 0; i < rawModules.length; i++) {
        var mod = rawModules[i];
        
        // skip system modules if excludeSystem is enabled
        if (excludeSystem && isSystemModule(mod.name, mod.path)) {
            continue;
        }
        
        var moduleEndAddress = mod.base.add(mod.size);

        // version for internal js use
        internalUseModules.push({
            id: internalUseModules.length, // assign sequential id
            name: mod.name,
            base: mod.base,
            size: mod.size,
            path: mod.path,
            end: moduleEndAddress
        });

        // version for sending to python
        pythonSendModules.push({
            id: internalUseModules.length - 1,
            name: mod.name,
            base: mod.base.toString(),
            size: mod.size,
            path: mod.path,
            end: moduleEndAddress.toString()
        });
    }
    return { internal: internalUseModules, forPython: pythonSendModules };
}

// initial module processing
var moduleProcessingResult = prepareModuleData();
var modulesForJsLogic = moduleProcessingResult.internal;
var modulesForPythonHost = moduleProcessingResult.forPython;

// send the python-friendly module list to the host
send({'type': 'modules', 'data': modulesForPythonHost});

// create a lookup table: module_path -> {id: module_id, start: module_base_nativepointer}
var modulePathToIdMap = {};
modulesForJsLogic.forEach(function (moduleEntry) {
    modulePathToIdMap[moduleEntry.path] = {id: moduleEntry.id, start: moduleEntry.base};
});

// create filtered module map based on whitelist
var filteredModuleMap = new ModuleMap(function (m) {
    if (whitelistedModules.indexOf('all') >= 0) {
        return !excludeSystem || !isSystemModule(m.name, m.path);
    }
    // check if module name matches whitelist
    return whitelistedModules.some(item => m.name.toLowerCase().includes(item.toLowerCase()));
});

// convert basic blocks to drcov format
function convertBasicBlocksToDrcov(basicBlockEvents, activeModuleMap, pathToIdLookup) {
    var buffer = new ArrayBuffer(DRCOV_BB_ENTRY_SIZE_BYTES * basicBlockEvents.length);
    var numEntriesWritten = 0;

    for (var i = 0; i < basicBlockEvents.length; ++i) {
        var blockEvent = basicBlockEvents[i];
        var startAddress = blockEvent[0];
        var endAddress = blockEvent[1];

        var modulePath = activeModuleMap.findPath(startAddress);
        if (modulePath === null) {
            continue;
        }

        var moduleInfo = pathToIdLookup[modulePath];
        if (!moduleInfo || !(moduleInfo.start instanceof NativePointer)) {
            continue;
        }

        var offset = startAddress.sub(moduleInfo.start).toInt32();
        var size = endAddress.sub(startAddress).toInt32();
        var moduleId = moduleInfo.id;

        var currentOffsetBytes = numEntriesWritten * DRCOV_BB_ENTRY_SIZE_BYTES;

        // write offset (uint32_t)
        new Uint32Array(buffer, currentOffsetBytes, 1)[0] = offset;
        // write size (uint16_t) and mod_id (uint16_t)
        var uint16View = new Uint16Array(buffer, currentOffsetBytes + 4, 2);
        uint16View[0] = size;
        uint16View[1] = moduleId;

        ++numEntriesWritten;
    }

    if (numEntriesWritten === 0) {
        return null;
    }
    return new Uint8Array(buffer, 0, numEntriesWritten * DRCOV_BB_ENTRY_SIZE_BYTES);
}

// stalker configuration
Stalker.trustThreshold = 0;

// track active stalkers
var activeStalkers = new Set();

// start stalking thread if needed
function startStalkingThreadIfNeeded(threadId) {
    var shouldStalkThisThread = threadIdList.indexOf('all') >= 0 || threadIdList.indexOf(threadId) >= 0;

    if (!shouldStalkThisThread) {
        return;
    }

    if (activeStalkers.has(threadId)) {
        return; // already stalking
    }

    if (verbose) console.log('Stalking thread ' + threadId);
    activeStalkers.add(threadId);

    // Configure events based on hit counting mode
    var stalkerEvents = useHitCounting ? {
        block: true    // Use block events for hit counting
    } : {
        compile: true  // Use compile events for coverage only
    };
    
    // Convert thread ID to unsigned integer for Frida
    // On Linux, thread IDs can be negative, but Stalker.follow expects unsigned
    var unsignedThreadId = threadId >>> 0;
    
    Stalker.follow(unsignedThreadId, {
        events: stalkerEvents,
        onReceive: function (rawStalkerEvents) {
            try {
                var parsedBasicBlocks = Stalker.parse(rawStalkerEvents, {stringify: false, annotate: false});

                if (parsedBasicBlocks && parsedBasicBlocks.length > 0) {
                    var drcovFormattedBlocks = convertBasicBlocksToDrcov(parsedBasicBlocks, filteredModuleMap, modulePathToIdMap);
                    if (drcovFormattedBlocks && drcovFormattedBlocks.buffer.byteLength > 0) {
                        send({type: 'bbs'}, drcovFormattedBlocks);
                    }
                }
            } catch (e) {
                console.error('Error in stalker onReceive for thread ' + threadId + ':', e.message);
            }
        }
    });
}

// thread observer for handling both existing and new threads
var threadObserver = Process.attachThreadObserver({
    onAdded: function (thread) {
        startStalkingThreadIfNeeded(thread.id);
    },
    onRemoved: function (thread) {
        if (activeStalkers.has(thread.id)) {
            activeStalkers.delete(thread.id);
            if (verbose) console.log('Thread ' + thread.id + ' removed from stalker tracking');
        }
    }
});

if (verbose) console.log('Thread observer ready');

// handle shutdown
recv(function(message) {
    if (message.type === 'shutdown') {
        if (verbose) console.log('Received shutdown request');
        
        // stop all stalkers
        activeStalkers.forEach(function(threadId) {
            try {
                Stalker.unfollow(threadId);
            } catch (e) {
                console.error('Error stopping stalker for thread ' + threadId + ':', e.message);
            }
        });
        activeStalkers.clear();
        
        // detach thread observer
        if (threadObserver) {
            threadObserver.detach();
        }
        
        send({type: 'shutdown_complete'});
    }
});

// send ready signal
send({type: 'ready'});
"""


class StalkDrcovTracer:
    """Main tracer class for basic block coverage collection"""

    def __init__(self, args):
        self.args = args

        # Frida objects
        self.device = None
        self.session = None
        self.script = None
        self.pid = None

        # State tracking
        self.running = False
        self.shutdown_complete = False

        # Data storage - depends on hit counting mode
        self.modules = []
        self._initialize_storage()

    def _initialize_storage(self):
        """Initialize basic blocks storage based on mode"""
        if self.args.hits:
            # Dict for hit counting: bb_entry_bytes -> count
            self.basic_blocks = {}
            print("[*] Coverage mode: Hit counting (using block events)")
        else:
            # Set for coverage tracking (standard drcov behavior)
            self.basic_blocks = set()
            print("[*] Coverage mode: Basic (using compile events)")

    def start_tracing(self):
        """Start the tracing process"""
        try:
            # get device
            self.device = self._get_device()

            # attach or spawn
            if self.args.spawn:
                self._spawn_process()
            else:
                self._attach_process()

            # inject script
            self._inject_script()

            # resume if spawned
            if self.args.spawn:
                self.device.resume(self.pid)
                print("[+] Process resumed")

            self.running = True

        except Exception as e:
            # cleanup on failure
            if hasattr(self, "session") and self.session:
                try:
                    self.session.detach()
                except:
                    pass
            raise e

    def _get_device(self):
        """Get the Frida device"""
        try:
            if self.args.host:
                manager = frida.get_device_manager()
                device = manager.add_remote_device(self.args.host)
                print(f"[*] Using remote device: {self.args.host}")
            else:
                device = frida.get_device(self.args.device)
                print(f"[*] Using device: {device.id}")
            return device
        except Exception as e:
            raise RuntimeError(f"Failed to get Frida device: {e}")

    def _spawn_process(self):
        """Spawn a new process"""
        try:
            target_path = self.args.target
            print(f"[*] Spawning: {target_path}")

            spawn_options = {}
            if self.args.disable_aslr:
                spawn_options["aslr"] = "disable"
                print("[*] ASLR disabled for spawned process")

            # Build command line with target and arguments
            cmd_line = [target_path] + self.args.target_args
            if self.args.target_args:
                print(f"[*] Spawning with arguments: {' '.join(cmd_line)}")
            self.pid = self.device.spawn(cmd_line, **spawn_options)
            print(f"[+] Spawned process with PID: {self.pid}")

            self.session = self.device.attach(self.pid)
            print(f"[+] Attached to spawned process")

        except frida.ExecutableNotFoundError:
            raise RuntimeError(f"Executable not found: {target_path}")
        except Exception as e:
            raise RuntimeError(f"Failed to spawn process: {e}")

    def _attach_process(self):
        """Attach to existing process"""
        try:
            target = self.args.target

            # try to parse as PID first
            try:
                self.pid = int(target)
                print(f"[*] Attaching to PID: {self.pid}")
                self.session = self.device.attach(self.pid)
                print(f"[+] Attached to PID: {self.pid}")
            except ValueError:
                # treat as process name
                print(f"[*] Looking for process: {target}")
                try:
                    process = self.device.get_process(target)
                    self.pid = process.pid
                    print(f"[*] Found process '{target}' with PID: {self.pid}")
                    self.session = self.device.attach(self.pid)
                    print(f"[+] Attached to process")
                except frida.ProcessNotFoundError:
                    # fallback to enumeration
                    print(
                        f"[*] Process '{target}' not found by direct lookup, searching..."
                    )
                    try:
                        processes = self.device.enumerate_processes()
                        matches = [
                            p
                            for p in processes
                            if target.lower() in p.name.lower() or str(p.pid) == target
                        ]

                        if not matches:
                            available_processes = [
                                f"{p.pid}: {p.name}" for p in processes[:10]
                            ]
                            available_str = "\n".join(available_processes)
                            if len(processes) > 10:
                                available_str += (
                                    f"\n... and {len(processes) - 10} more processes"
                                )

                            raise RuntimeError(
                                f"Process '{target}' not found.\n"
                                f"Available processes (showing first 10):\n{available_str}\n\n"
                                f"Use a valid PID or process name."
                            )
                        elif len(matches) > 1:
                            print(f"[!] Multiple processes match '{target}':")
                            for p in matches:
                                print(f"    PID: {p.pid}, Name: {p.name}")
                            self.pid = matches[0].pid
                            print(f"[*] Using first match: PID {self.pid}")
                        else:
                            self.pid = matches[0].pid
                            print(
                                f"[*] Found process: PID {self.pid}, Name: {matches[0].name}"
                            )

                        self.session = self.device.attach(self.pid)
                        print(f"[+] Attached to process")

                    except Exception as e:
                        raise RuntimeError(
                            f"Failed to enumerate or attach to processes: {e}"
                        )
            except frida.ProcessNotFoundError:
                raise RuntimeError(
                    f"Process with PID {self.pid} not found or access denied"
                )
            except Exception as e:
                raise RuntimeError(f"Failed to attach to process: {e}")

        except Exception as e:
            raise RuntimeError(f"Failed to attach to process: {e}")

    def _inject_script(self):
        """Inject the JavaScript agent"""
        try:
            # prepare configuration
            config = {
                "whitelistedModules": self.args.whitelist_modules or ["all"],
                "threadIdList": self.args.thread_id or ["all"],
                "excludeSystem": self.args.no_system,
                "useHitCounting": self.args.hits,
                "verbose": self.args.verbose,
            }

            # inject script with properly escaped JSON
            config_json = json.dumps(config)
            config_json_escaped = config_json.replace("\\", "\\\\").replace("'", "\\'")
            script_code = js_agent_code.replace(
                "CONFIG_JSON_PLACEHOLDER", config_json_escaped
            )

            self.script = self.session.create_script(script_code)
            self.script.on("message", self._on_message)
            self.script.load()

        except Exception as e:
            raise RuntimeError(f"Failed to inject JavaScript agent: {e}")

    def _on_message(self, message, data):
        """Handle messages from the JS agent"""
        try:
            if message["type"] == "error":
                print(f"[!] Script error: {message}")
                return

            if message["type"] == "send":
                payload = message.get("payload", {})
                msg_type = payload.get("type")

                if msg_type == "ready":
                    print("[+] Agent ready")

                elif msg_type == "modules":
                    self.modules = payload.get("data", [])
                    print(f"[*] Modules: {len(self.modules)} loaded")

                elif msg_type == "bbs":
                    if data:
                        self._process_basic_blocks(data)

                elif msg_type == "shutdown_complete":
                    print("[*] Shutdown complete")
                    self.shutdown_complete = True

        except Exception as e:
            print(f"[!] Error processing message: {e}")

    def _process_basic_blocks(self, bb_data_buffer):
        """Process basic block data from JS agent"""
        if not bb_data_buffer or len(bb_data_buffer) == 0:
            return

        if len(bb_data_buffer) % DRCOV_BB_ENTRY_SIZE_BYTES != 0:
            print(f"[!] Invalid BB data length: {len(bb_data_buffer)}")
            return

        # process each basic block entry
        for i in range(0, len(bb_data_buffer), DRCOV_BB_ENTRY_SIZE_BYTES):
            bb_entry = bb_data_buffer[i : i + DRCOV_BB_ENTRY_SIZE_BYTES]

            if self.args.hits:
                # track hit counts in dict
                if bb_entry in self.basic_blocks:
                    self.basic_blocks[bb_entry] += 1
                else:
                    self.basic_blocks[bb_entry] = 1
            else:
                # just track coverage in set
                self.basic_blocks.add(bb_entry)

    def stop_tracing(self):
        """Stop tracing and cleanup"""
        if not self.running:
            return

        print("[*] Stopping tracing...")
        self.running = False

        if self.script:
            try:
                print("[*] Sending shutdown signal...")
                self.script.post({"type": "shutdown"})

                # wait for shutdown complete
                timeout = 5.0
                start_time = time.time()
                while (
                    not self.shutdown_complete and (time.time() - start_time) < timeout
                ):
                    time.sleep(0.1)

                if not self.shutdown_complete:
                    print("[!] Timeout waiting for shutdown")

            except Exception as e:
                print(f"[!] Error during shutdown: {e}")

        # cleanup session
        if self.session:
            try:
                self.session.detach()
                print("[+] Session detached")
            except Exception as e:
                print(f"[!] Error detaching session: {e}")

    def save_coverage(self):
        """Save coverage data to drcov file"""
        try:
            output_file = self.args.output
            if not output_file:
                output_file = "frida-cov.drcov"

            # Generate status message
            block_count = len(self.basic_blocks)
            if self.args.hits:
                total_hits = sum(self.basic_blocks.values())
                status_msg = f"[*] Saving {block_count:,} unique basic blocks ({total_hits:,} total hits) to '{output_file}'..."
            else:
                status_msg = f"[*] Saving {block_count:,} unique basic blocks to '{output_file}'..."
            print(status_msg)

            # create drcov header
            header = self._create_drcov_header()

            # create drcov body
            body = self._create_drcov_body()

            # write file
            with open(output_file, "wb") as f:
                f.write(header)
                f.write(body)

            print(f"[+] Coverage data saved to: {output_file}")

        except Exception as e:
            print(f"[!] Error saving coverage: {e}")

    def _create_drcov_header(self):
        """Create drcov file header"""
        lines = []
        lines.append("DRCOV VERSION: 2")
        # Set flavor based on hit counting mode
        if self.args.hits:
            lines.append("DRCOV FLAVOR: drcov-hits")
        else:
            lines.append("DRCOV FLAVOR: frida")

        if not self.modules:
            lines.append("Module Table: version 2, count 0")
        else:
            lines.append(f"Module Table: version 2, count {len(self.modules)}")

        lines.append("Columns: id, base, end, entry, checksum, timestamp, path")

        for module in self.modules:
            line = "%3d, %#016x, %#016x, %#016x, %#08x, %#08x, %s" % (
                module["id"],
                int(module["base"], 16),
                int(module["end"], 16),
                0,  # entry point
                0,  # checksum
                0,  # timestamp
                module["name"],  # Use basename instead of full path
            )
            lines.append(line)

        return ("\n".join(lines) + "\n").encode("utf-8")

    def _create_drcov_body(self):
        """Create drcov file body (standard or hit count format)"""
        if self.args.hits:
            return self._create_hit_count_body()
        else:
            return self._create_standard_body()

    def _create_standard_body(self):
        """Create standard drcov body (coverage only)"""
        sorted_bbs = sorted(list(self.basic_blocks))
        bb_header = f"BB Table: {len(sorted_bbs)} bbs\n".encode("utf-8")
        bb_data = b"".join(sorted_bbs)
        return bb_header + bb_data

    def _create_hit_count_body(self):
        """Create drcov body with hit count table"""
        # Sort basic blocks for deterministic output
        sorted_bb_items = sorted(self.basic_blocks.items())
        bb_entries = [bb_entry for bb_entry, count in sorted_bb_items]
        hit_counts = [count for bb_entry, count in sorted_bb_items]

        # Create BB Table
        bb_header = f"BB Table: {len(bb_entries)} bbs\n".encode("utf-8")
        bb_data = b"".join(bb_entries)

        # Create Hit Count Table (as per proposal specification)
        hit_header = f"Hit Count Table: version 1, count {len(hit_counts)}\n".encode(
            "utf-8"
        )
        hit_data = b"".join(struct.pack("<I", count) for count in hit_counts)

        return bb_header + bb_data + hit_header + hit_data


def signal_handler(signum, frame):
    """Handle signals for graceful shutdown"""
    print(f"\n[!] Received signal {signum}, shutting down...")
    if hasattr(signal_handler, "tracer"):
        signal_handler.tracer.stop_tracing()


def main():
    parser = argparse.ArgumentParser(
        description="Frida-based basic block tracer outputting drcov format",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # Target specification
    parser.add_argument("target", help="Process ID, process name, or executable path")
    parser.add_argument(
        "target_args",
        nargs="*",
        help="Arguments to pass to spawned process (use after --)",
    )

    # Execution mode
    parser.add_argument(
        "-s",
        "--spawn",
        action="store_true",
        help="Spawn new process instead of attaching",
    )
    parser.add_argument(
        "--disable-aslr",
        action="store_true",
        help="Disable ASLR for spawned process (macOS only)",
    )

    # Output options
    parser.add_argument(
        "-o",
        "--output",
        default="frida-cov.drcov",
        help="Output drcov file path (default: frida-cov.drcov)",
    )
    parser.add_argument(
        "--hits",
        action="store_true",
        help="Enable hit count tracking (uses block events, generates drcov-hits format)",
    )

    # Filtering options
    parser.add_argument(
        "-w",
        "--whitelist-modules",
        action="append",
        default=[],
        help="Module name to trace (can be repeated, default: all modules)",
    )
    parser.add_argument(
        "-t",
        "--thread-id",
        action="append",
        default=[],
        help="Thread ID to trace (can be repeated, default: all threads)",
    )
    parser.add_argument(
        "--no-system", action="store_true", help="Exclude system modules from tracing"
    )

    # Control options
    parser.add_argument(
        "--timeout", type=int, help="Maximum collection time in seconds"
    )

    # Device options
    parser.add_argument(
        "-D", "--device", default="local", help="Frida device (default: local)"
    )
    parser.add_argument("-H", "--host", help="Connect to remote frida-server")

    # Debug options
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    # create tracer
    tracer = StalkDrcovTracer(args)

    # setup signal handlers
    signal_handler.tracer = tracer
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        # start tracing
        tracer.start_tracing()
        print("[*] Tracing started. Press Ctrl+C to stop and save.")

        # wait for completion
        if args.timeout:
            time.sleep(args.timeout)
            tracer.stop_tracing()
        else:
            # wait for interrupt
            while tracer.running:
                try:
                    time.sleep(0.1)

                    # check if spawned process has exited
                    if args.spawn and tracer.pid:
                        try:
                            processes = tracer.device.enumerate_processes()
                            process_exists = any(p.pid == tracer.pid for p in processes)
                            if not process_exists:
                                print("[*] Spawned process has exited")
                                tracer.stop_tracing()
                                break
                        except:
                            pass  # ignore enumeration errors

                except KeyboardInterrupt:
                    print("\n[!] Interrupted by user")
                    tracer.stop_tracing()
                    break

    except frida.ProcessNotFoundError:
        print(f"[-] Process not found: {args.target}")
        sys.exit(1)
    except frida.PermissionDeniedError:
        print(f"[-] Permission denied. Try with elevated privileges.")
        sys.exit(1)
    except RuntimeError as e:
        print(f"[-] Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)
    else:
        # only run this if no exceptions occurred (tracer is properly initialized)
        try:
            # save results
            tracer.save_coverage()
        except Exception as e:
            print(f"[-] Error saving coverage: {e}")
            if args.verbose:
                import traceback

                traceback.print_exc()


if __name__ == "__main__":
    main()
