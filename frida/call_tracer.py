#!/usr/bin/env python3

"""
call_tracer.py
A frida-based call tracer that monitors function calls within specified functions.

Example usage:

# install frida-tools via uv
uv tool install frida-tools

# run python with uv
uv tool run --from frida-tools python ...

# trace and show summary in terminal (no file output)
python call_tracer.py -p 1234 -F 0x401000

# trace specific functions and save to file
python call_tracer.py -p 1234 -F 0x401000 -F 0x402000 -o traces.json

# trace by function name with symbols
python call_tracer.py myapp.exe -n malloc -n free -o calls.csv --format csv

# spawn and trace with timeout
python call_tracer.py -s ./target_binary -F 0x401000 -t 30
"""

from __future__ import print_function

import argparse
import json
import csv
import os
import signal
import sys
import time
import struct
import gzip
from dataclasses import dataclass, field
from typing import List, Tuple, Dict, Optional, Any, Set
from collections import defaultdict, Counter
from enum import Enum

import frida

# constants
VERSION = "1.0.0"
BINARY_MAGIC = b"CTRC"
BINARY_VERSION = 1

# frida javascript agent code
js_agent_code = """
"use strict";

// configuration passed from python
const config = %s;  // {functions: [...], modules: [...], monitorAll: bool}
const monitoredFunctions = config.functions || [];
const targetModules = config.modules || [];
const monitorAll = config.monitorAll || false;

// per-thread state tracking
const threadState = new Map();

// track which functions we're currently inside (per thread)
const functionContextStack = new Map();

// track active stalkers per thread
const activeStalkers = new Set();

// statistics
let totalCalls = 0;
const functionStats = new Map(); // func_addr -> { calls: number, threads: Set }

// collected calls buffer
const callBuffer = [];
const MAX_BUFFER_SIZE = 1000;  // send when buffer reaches this size

// periodic buffer flush
function flushBuffer() {
    try {
        if (callBuffer.length > 0) {
            send({
                type: 'calls',
                data: callBuffer.splice(0)
            });
        }
    } catch (e) {
        console.error('Error flushing buffer:', e.message);
    }
}

// flush buffer every 500ms
setInterval(flushBuffer, 500);

// initialize function statistics
monitoredFunctions.forEach(func => {
    functionStats.set(func.address, { calls: 0, threads: new Set() });
});

// get or create thread state
function getThreadState(threadId) {
    if (!threadState.has(threadId)) {
        threadState.set(threadId, {
            depths: new Map(),
            stalking: false
        });
    }
    return threadState.get(threadId);
}

// get current function context for thread
function getCurrentFunctionContext(threadId) {
    const stack = functionContextStack.get(threadId);
    if (!stack || stack.length === 0) return null;
    return stack[stack.length - 1]; // top of stack
}

// process call event from stalker
function processCallEvent(sourceAddr, targetAddr, threadId) {
    try {
        const funcContext = getCurrentFunctionContext(threadId);
        if (!funcContext) return;
        
        // create call event
        const callData = {
            timestamp: Date.now() / 1000.0,
            thread_id: threadId,
            source_addr: sourceAddr.toString(),
            target_addr: targetAddr.toString(),
            function_context: funcContext,
            call_type: 'call'
        };
        
        // add to buffer
        callBuffer.push(callData);
        totalCalls++;
        
        // update function statistics
        const stats = functionStats.get(funcContext);
        if (stats) {
            stats.calls++;
            stats.threads.add(threadId);
        }
        
        // send if buffer is getting full
        if (callBuffer.length >= MAX_BUFFER_SIZE) {
            send({
                type: 'calls',
                data: callBuffer.splice(0)  // remove all and send
            });
        }
    } catch (e) {
        console.error('Error processing call event:', e.message);
    }
}

// function entry handler
function enterMonitoredFunction(funcAddr, threadId) {
    try {
        const state = getThreadState(threadId);
        const depth = state.depths.get(funcAddr) || 0;
        state.depths.set(funcAddr, depth + 1);
        
        // push to context stack
        if (!functionContextStack.has(threadId)) {
            functionContextStack.set(threadId, []);
        }
        functionContextStack.get(threadId).push(funcAddr);
        
        // create function entry event
        const entryEvent = {
            timestamp: Date.now() / 1000.0,
            thread_id: threadId,
            source_addr: "0x0",  // entry point
            target_addr: funcAddr,
            function_context: funcAddr,
            call_type: 'entry'
        };
        
        callBuffer.push(entryEvent);
        totalCalls++;
        
        // update function statistics
        const stats = functionStats.get(funcAddr);
        if (stats) {
            stats.calls++;
            stats.threads.add(threadId);
        }
        
        // send buffer if getting full
        if (callBuffer.length >= MAX_BUFFER_SIZE) {
            send({
                type: 'calls',
                data: callBuffer.splice(0)
            });
        }
        
        // start stalking if this is the first monitored function entry for this thread
        if (!state.stalking && !activeStalkers.has(threadId)) {
            console.log(`Starting stalker for thread ${threadId}`);
            
            try {
                Stalker.follow(threadId, {
                    events: {
                        call: true
                    },
                    onReceive: function(events) {
                        try {
                            const parsed = Stalker.parse(events);
                            
                            // process each call event
                            let i = 0;
                            while (i < parsed.length) {
                                // each call event is 3 elements: [address, target, depth]
                                if (i + 2 < parsed.length) {
                                    const sourceAddr = parsed[i];
                                    const targetAddr = parsed[i + 1];
                                    processCallEvent(sourceAddr, targetAddr, threadId);
                                    i += 3;
                                } else {
                                    break;
                                }
                            }
                        } catch (e) {
                            console.error(`Error in stalker onReceive for thread ${threadId}:`, e.message);
                        }
                    }
                });
                
                state.stalking = true;
                activeStalkers.add(threadId);
            } catch (e) {
                console.error(`Error starting stalker for thread ${threadId}:`, e.message);
            }
        }
    } catch (e) {
        console.error('Error in enterMonitoredFunction:', e.message);
    }
}

// function exit handler
function exitMonitoredFunction(funcAddr, threadId) {
    try {
        const state = getThreadState(threadId);
        const depth = state.depths.get(funcAddr) || 0;
        
        if (depth > 0) {
            // create function exit event
            const exitEvent = {
                timestamp: Date.now() / 1000.0,
                thread_id: threadId,
                source_addr: funcAddr,
                target_addr: "0x0",  // exit point
                function_context: funcAddr,
                call_type: 'exit'
            };
            
            callBuffer.push(exitEvent);
            totalCalls++;
            
            state.depths.set(funcAddr, depth - 1);
            
            // pop from context stack
            const stack = functionContextStack.get(threadId);
            if (stack && stack.length > 0) {
                const idx = stack.lastIndexOf(funcAddr);
                if (idx !== -1) {
                    stack.splice(idx, 1);
                }
            }
            
            // send buffer if getting full
            if (callBuffer.length >= MAX_BUFFER_SIZE) {
                send({
                    type: 'calls',
                    data: callBuffer.splice(0)
                });
            }
            
            // stop stalking if we're exiting all monitored functions in this thread
            if (depth === 1) {
                let stillInMonitoredFunction = false;
                state.depths.forEach((d, addr) => {
                    if (d > 0 && addr !== funcAddr) {
                        stillInMonitoredFunction = true;
                    }
                });
                
                if (!stillInMonitoredFunction && state.stalking) {
                    console.log(`Stopping stalker for thread ${threadId}`);
                    try {
                        Stalker.unfollow(threadId);
                        state.stalking = false;
                        activeStalkers.delete(threadId);
                        
                        // Check if this was the last active thread
                        if (activeStalkers.size === 0) {
                            console.log('All threads completed, flushing final data...');
                            flushBuffer();
                            cleanup();
                            
                            // Signal final completion
                            send({ type: 'process_complete' });
                        } else {
                            console.log(`Thread ${threadId} completed, ${activeStalkers.size} threads still active`);
                        }
                    } catch (e) {
                        console.error(`Error stopping stalker for thread ${threadId}:`, e.message);
                    }
                }
            }
        }
    } catch (e) {
        console.error('Error in exitMonitoredFunction:', e.message);
    }
}

// setup function hooks
function setupFunctionHooks() {
    const resolved = [];
    const failed = [];
    
    monitoredFunctions.forEach(func => {
        try {
            const addr = ptr(func.address);
            
            // verify the address is readable
            addr.readU8();
            
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    const threadId = Process.getCurrentThreadId();
                    enterMonitoredFunction(func.address, threadId);
                },
                onLeave: function(retval) {
                    const threadId = Process.getCurrentThreadId();
                    exitMonitoredFunction(func.address, threadId);
                }
            });
            
            resolved.push(func);
            console.log(`Hooked ${func.address} (${func.name || 'unnamed'})`);
            
        } catch (e) {
            console.error(`Failed to hook ${func.address}: ${e.message}`);
            failed.push(func);
        }
    });
    
    send({
        type: 'hook_status',
        resolved: resolved,
        failed: failed
    });
}

// resolve function names to addresses
function resolveFunctionNames(names) {
    const resolved = [];
    
    names.forEach(name => {
        let found = false;
        
        // try module exports
        Process.enumerateModules().forEach(module => {
            if (found) return;
            
            module.enumerateExports().forEach(exp => {
                if (exp.name === name) {
                    resolved.push({
                        address: exp.address.toString(),
                        name: exp.name,
                        module: module.name
                    });
                    found = true;
                }
            });
        });
        
        if (!found) {
            console.warn(`Could not resolve function: ${name}`);
        }
    });
    
    return resolved;
}

// expand address ranges
function expandAddressRanges(ranges) {
    const functions = [];
    
    ranges.forEach(range => {
        const [start, end] = range.split(':').map(a => parseInt(a, 16));
        
        // for now, just hook the start address
        functions.push({
            address: '0x' + start.toString(16),
            name: `range_${start.toString(16)}_${end.toString(16)}`
        });
    });
    
    return functions;
}

// discover functions in specified modules
function discoverModuleFunctions(moduleNames) {
    const functions = [];
    
    Process.enumerateModules().forEach(module => {
        if (moduleNames.length === 0 || moduleNames.includes(module.name)) {
            console.log(`Discovering functions in module: ${module.name}`);
            
            // enumerate exports
            module.enumerateExports().forEach(exp => {
                if (exp.type === 'function') {
                    functions.push({
                        address: exp.address.toString(),
                        name: exp.name,
                        module: module.name
                    });
                }
            });
        }
    });
    
    console.log(`Discovered ${functions.length} functions in ${moduleNames.length > 0 ? moduleNames.join(', ') : 'all modules'}`);
    return functions;
}

// discover all functions in all modules (for monitor-all mode)
function discoverAllFunctions() {
    const functions = [];
    
    Process.enumerateModules().forEach(module => {
        console.log(`Discovering all functions in module: ${module.name}`);
        
        // enumerate exports
        module.enumerateExports().forEach(exp => {
            if (exp.type === 'function') {
                functions.push({
                    address: exp.address.toString(),
                    name: exp.name,
                    module: module.name
                });
            }
        });
    });
    
    console.log(`Discovered ${functions.length} total functions in all modules`);
    return functions;
}

// send final data on cleanup
function cleanup() {
    console.log(`Final cleanup: buffer has ${callBuffer.length} calls, total calls: ${totalCalls}`);
    
    // send any remaining calls
    if (callBuffer.length > 0) {
        send({
            type: 'calls',
            data: callBuffer.splice(0)  // clear the buffer
        });
    }
    
    // send final statistics
    const stats = {};
    functionStats.forEach((stat, addr) => {
        stats[addr] = {
            calls: stat.calls,
            threads: stat.threads.size
        };
    });
    
    send({
        type: 'statistics',
        total_calls: totalCalls,
        function_stats: stats
    });
}

// handle different monitoring modes
if (monitorAll) {
    // monitor all functions in all modules
    const allFunctions = discoverAllFunctions();
    allFunctions.forEach(f => monitoredFunctions.push(f));
} else if (targetModules.length > 0) {
    // monitor functions in specific modules
    const moduleFunctions = discoverModuleFunctions(targetModules);
    moduleFunctions.forEach(f => monitoredFunctions.push(f));
}

// process address ranges if any
const ranges = monitoredFunctions.filter(f => f.range).map(f => f.range);
if (ranges.length > 0) {
    const rangeFunctions = expandAddressRanges(ranges);
    rangeFunctions.forEach(f => monitoredFunctions.push(f));
}

// process function names if any
const namesToResolve = monitoredFunctions.filter(f => f.name && !f.address).map(f => f.name);
if (namesToResolve.length > 0) {
    const resolved = resolveFunctionNames(namesToResolve);
    resolved.forEach(r => monitoredFunctions.push(r));
}

// filter out functions without addresses
const validFunctions = monitoredFunctions.filter(f => f.address);

// update monitored functions list
monitoredFunctions.length = 0;
validFunctions.forEach(f => monitoredFunctions.push(f));

// setup hooks
if (monitoredFunctions.length > 0) {
    setupFunctionHooks();
} else {
    send({
        type: 'error',
        message: 'No valid functions to monitor'
    });
}

// register cleanup
Script.bindWeak(globalThis, cleanup);

// handle messages from python
recv(function(message) {
    if (message.type === 'shutdown') {
        console.log('Received shutdown request, stopping all stalkers...');
        
        // Stop all active stalkers
        activeStalkers.forEach(threadId => {
            try {
                console.log(`Force stopping stalker for thread ${threadId}`);
                Stalker.unfollow(threadId);
            } catch (e) {
                console.error(`Error stopping stalker for thread ${threadId}:`, e.message);
            }
        });
        activeStalkers.clear();
        
        // Flush all remaining data
        flushBuffer();
        cleanup();
        send({ type: 'shutdown_complete' });
    }
});

// send ready signal
send({ type: 'ready' });
"""


# data structures
@dataclass
class CallEvent:
    timestamp: float
    thread_id: int
    source_addr: int
    target_addr: int
    function_context: int
    call_type: str


@dataclass
class FunctionContext:
    address: int
    name: Optional[str]
    module: Optional[str] = None
    total_calls: int = 0
    unique_threads: Set[int] = field(default_factory=set)
    unique_targets: Set[int] = field(default_factory=set)


@dataclass
class CallSummary:
    total_calls: int
    unique_threads: int
    duration: float
    calls_per_second: float
    functions: List[Dict[str, Any]]
    top_targets: List[Tuple[str, int]]
    thread_distribution: Dict[int, int]


class CallTracer:
    def __init__(self, args):
        self.args = args
        self.start_time = time.time()
        self.end_time = None
        self.running = False
        self.script = None
        self.session = None
        self.device = None
        self.pid = None

        # data storage
        self.call_events = []
        self.function_contexts = {}  # addr -> FunctionContext
        self.monitored_functions = []
        self.shutdown_complete = False

        # prepare monitored functions
        self._prepare_monitored_functions()

    def _prepare_monitored_functions(self):
        """Prepare the list of functions to monitor"""
        functions = []

        # add functions by address
        for addr in self.args.hook_func or []:
            try:
                addr_int = int(addr, 16) if addr.startswith("0x") else int(addr)
                func_ctx = FunctionContext(address=addr_int, name=None)
                self.function_contexts[addr] = func_ctx
                functions.append({"address": addr, "name": None})
            except ValueError:
                print(f"[-] Invalid address format: {addr}")
                sys.exit(1)

        # add functions by name
        for name in self.args.hook_name or []:
            functions.append({"address": None, "name": name})

        # add address ranges
        for range_str in self.args.hook_range or []:
            if ":" not in range_str:
                print(f"[-] Invalid range format: {range_str}")
                sys.exit(1)
            functions.append({"range": range_str})

        self.monitored_functions = functions

    def start_tracing(self):
        """Start the tracing session"""
        try:
            # setup device
            self.device = self._get_device()

            # attach or spawn
            if self.args.spawn:
                if not os.path.exists(self.args.target):
                    raise FileNotFoundError(f"Target binary not found: {self.args.target}")
                
                self.pid = self.device.spawn([self.args.target])
                self.session = self.device.attach(self.pid)
                print(f"[+] Spawned process with PID: {self.pid}")
            else:
                try:
                    self.pid = int(self.args.target)
                    self.session = self.device.attach(self.pid)
                    print(f"[+] Attached to PID: {self.pid}")
                except ValueError:
                    # Try to attach by process name
                    try:
                        self.session = self.device.attach(self.args.target)
                        print(f"[+] Attached to process: {self.args.target}")
                    except frida.ProcessNotFoundError:
                        raise frida.ProcessNotFoundError(
                            f"Process '{self.args.target}' not found. "
                            "Please specify a valid PID or process name."
                        )

            # validate we have something to monitor
            if not self.monitored_functions and not self.args.module and not self.args.monitor_all:
                raise ValueError("No functions, modules, or monitor-all specified")

            # prepare configuration for JS agent
            config = {
                "functions": self.monitored_functions,
                "modules": self.args.module or [],
                "monitorAll": self.args.monitor_all,
            }

            # inject script
            script_code = js_agent_code % json.dumps(config)

            try:
                self.script = self.session.create_script(script_code)
                self.script.on("message", self._on_message)
                self.script.load()
            except Exception as e:
                raise RuntimeError(f"Failed to inject JavaScript agent: {e}")

            # resume if spawned
            if self.args.spawn:
                self.device.resume(self.pid)
                print("[+] Process resumed")

            self.running = True

            # start timeout if specified
            if self.args.timeout:
                timer = threading.Timer(self.args.timeout, self._timeout_handler)
                timer.daemon = True
                timer.start()

        except Exception as e:
            # Cleanup on failure
            if hasattr(self, 'session') and self.session:
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

    def _on_message(self, message, data):
        """Handle messages from the JS agent"""
        if message["type"] == "error":
            print(f"[!] Script error: {message}")
            return

        if message["type"] == "send":
            payload = message.get("payload", {})
            msg_type = payload.get("type")

            if msg_type == "ready":
                print("[+] Agent ready and monitoring")

            elif msg_type == "hook_status":
                resolved = payload.get("resolved", [])
                failed = payload.get("failed", [])

                # update function contexts
                for func in resolved:
                    addr = func["address"]
                    if addr not in self.function_contexts:
                        func_ctx = FunctionContext(
                            address=int(addr, 16) if isinstance(addr, str) else addr,
                            name=func.get("name"),
                            module=func.get("module"),
                        )
                        self.function_contexts[addr] = func_ctx

                if failed:
                    print(f"[!] Failed to hook {len(failed)} functions")

            elif msg_type == "calls":
                # process batch of calls
                calls = payload.get("data", [])
                for call_data in calls:
                    try:
                        event = CallEvent(
                            timestamp=call_data["timestamp"],
                            thread_id=call_data["thread_id"],
                            source_addr=int(call_data["source_addr"], 16),
                            target_addr=int(call_data["target_addr"], 16),
                            function_context=int(call_data["function_context"], 16),
                            call_type=call_data["call_type"],
                        )
                        self.call_events.append(event)

                        # update function stats
                        func_addr = call_data["function_context"]
                        if func_addr in self.function_contexts:
                            ctx = self.function_contexts[func_addr]
                            ctx.total_calls += 1
                            ctx.unique_threads.add(event.thread_id)
                            ctx.unique_targets.add(event.target_addr)

                    except (KeyError, ValueError) as e:
                        if self.args.verbose:
                            print(f"[-] Error processing call: {e}")

            elif msg_type == "statistics":
                # final statistics
                self.final_stats = payload

            elif msg_type == "shutdown_complete":
                # script has finished cleanup, now we can safely unload
                print("[*] Received shutdown complete signal")
                self.shutdown_complete = True
                self._force_cleanup()

            elif msg_type == "process_complete":
                # target process has finished and data is flushed
                print("[*] Target process completed, all data collected")
                self.shutdown_complete = True

            elif msg_type == "error":
                print(f"[!] Error: {payload.get('message')}")

    def _timeout_handler(self):
        """Handle timeout"""
        print(f"\n[!] Timeout reached ({self.args.timeout}s)")
        self.stop_tracing()

    def stop_tracing(self):
        """Stop tracing and cleanup"""
        if not self.running:
            return  # Already stopped

        print("[*] Stopping tracing...")
        self.running = False
        self.end_time = time.time()

        if self.script:
            try:
                # Send shutdown signal  
                print("[*] Sending shutdown signal to script...")
                self.script.post({"type": "shutdown"})
            except Exception as e:
                print(f"[-] Warning: Error sending shutdown signal: {e}")
                self._force_cleanup()

    def _force_cleanup(self):
        """Force cleanup when normal shutdown fails"""
        if self.script:
            try:
                self.script.unload()
            except Exception as e:
                if self.args.verbose:
                    print(f"[-] Warning: Error unloading script: {e}")

        if self.session:
            try:
                self.session.detach()
            except Exception as e:
                if self.args.verbose:
                    print(f"[-] Warning: Error detaching session: {e}")

        print("[*] Tracing stopped.")

    def get_summary(self) -> CallSummary:
        """Generate a summary of the trace data"""
        duration = (self.end_time or time.time()) - self.start_time
        total_calls = len(self.call_events)

        # count unique threads
        unique_threads = set(e.thread_id for e in self.call_events)

        # count calls per target
        target_counts = Counter(hex(e.target_addr) for e in self.call_events)

        # count calls per thread
        thread_counts = Counter(e.thread_id for e in self.call_events)

        # prepare function summaries
        function_summaries = []
        for addr, ctx in self.function_contexts.items():
            function_summaries.append(
                {
                    "address": hex(ctx.address),
                    "name": ctx.name or "unnamed",
                    "calls": ctx.total_calls,
                    "threads": len(ctx.unique_threads),
                    "unique_targets": len(ctx.unique_targets),
                }
            )

        # sort functions by call count
        function_summaries.sort(key=lambda x: x["calls"], reverse=True)

        return CallSummary(
            total_calls=total_calls,
            unique_threads=len(unique_threads),
            duration=duration,
            calls_per_second=total_calls / duration if duration > 0 else 0,
            functions=function_summaries,
            top_targets=target_counts.most_common(10),
            thread_distribution=dict(thread_counts),
        )

    def print_summary(self):
        """Print a neat summary to stdout"""
        summary = self.get_summary()

        print("\n" + "=" * 60)
        print("                    CALL TRACE SUMMARY")
        print("=" * 60)

        print(f"\nTotal Calls:      {summary.total_calls:,}")
        print(f"Unique Threads:   {summary.unique_threads}")
        print(f"Duration:         {summary.duration:.2f}s")
        print(f"Calls/Second:     {summary.calls_per_second:.1f}")

        # Call type breakdown
        call_types = {}
        for event in self.call_events:
            call_types[event.call_type] = call_types.get(event.call_type, 0) + 1

        if call_types:
            print(f"\nCall Types:")
            print("-" * 30)
            for call_type, count in sorted(call_types.items()):
                print(f"{call_type:<12}: {count:>8,}")

        if summary.functions:
            print(f"\nMonitored Functions ({len(summary.functions)}):")
            print("-" * 60)
            print(
                f"{'Address':<18} {'Name':<20} {'Calls':>10} {'Threads':>8} {'Targets':>8}"
            )
            print("-" * 60)
            for func in summary.functions:
                name = func["name"][:20]
                print(
                    f"{func['address']:<18} {name:<20} {func['calls']:>10,} "
                    f"{func['threads']:>8} {func['unique_targets']:>8}"
                )

        if summary.top_targets:
            print(f"\nTop Call Targets:")
            print("-" * 40)
            print(f"{'Address':<18} {'Count':>10}")
            print("-" * 40)
            for addr, count in summary.top_targets:
                print(f"{addr:<18} {count:>10,}")

        if len(summary.thread_distribution) > 1:
            print(f"\nThread Distribution:")
            print("-" * 30)
            sorted_threads = sorted(
                summary.thread_distribution.items(), key=lambda x: x[1], reverse=True
            )
            for tid, count in sorted_threads[:5]:
                pct = (count / summary.total_calls) * 100
                print(f"Thread {tid:<8}: {count:>8,} calls ({pct:>5.1f}%)")
            if len(sorted_threads) > 5:
                print(f"... and {len(sorted_threads) - 5} more threads")

        print("\n" + "=" * 60)

    def export_results(self):
        """Export results to file"""
        output_file = self.args.output

        # handle compression
        if self.args.compress:
            if not output_file.endswith(".gz"):
                output_file += ".gz"

        # export based on format
        if self.args.format == "json":
            self._export_json(output_file)
        elif self.args.format == "csv":
            self._export_csv(output_file)
        elif self.args.format == "binary":
            self._export_binary(output_file)

        file_size = os.path.getsize(output_file)
        print(f"[+] Results saved to: {output_file} ({file_size:,} bytes)")

    def _export_json(self, filepath):
        """Export to JSON format"""
        summary = self.get_summary()

        data = {
            "metadata": {
                "version": VERSION,
                "target": self.args.target,
                "start_time": self.start_time,
                "end_time": self.end_time,
                "duration": summary.duration,
                "total_calls": summary.total_calls,
                "unique_threads": summary.unique_threads,
                "calls_per_second": summary.calls_per_second,
                "functions": summary.functions,
            },
            "calls": [
                {
                    "timestamp": e.timestamp,
                    "thread_id": e.thread_id,
                    "source_addr": hex(e.source_addr),
                    "target_addr": hex(e.target_addr),
                    "function_context": hex(e.function_context),
                    "call_type": e.call_type,
                }
                for e in self.call_events
            ],
        }

        if self.args.compress:
            with gzip.open(filepath, "wt", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        else:
            with open(filepath, "w") as f:
                json.dump(data, f, indent=2)

    def _export_csv(self, filepath):
        """Export to CSV format"""
        headers = [
            "timestamp",
            "thread_id",
            "source_addr",
            "target_addr",
            "function_context",
            "call_type",
        ]

        if self.args.compress:
            f = gzip.open(filepath, "wt", newline="", encoding="utf-8")
        else:
            f = open(filepath, "w", newline="")

        try:
            writer = csv.writer(f)
            writer.writerow(headers)

            for e in self.call_events:
                writer.writerow(
                    [
                        e.timestamp,
                        e.thread_id,
                        hex(e.source_addr),
                        hex(e.target_addr),
                        hex(e.function_context),
                        e.call_type,
                    ]
                )
        finally:
            f.close()

    def _export_binary(self, filepath):
        """Export to binary format"""
        if self.args.compress:
            f = gzip.open(filepath, "wb")
        else:
            f = open(filepath, "wb")

        try:
            # header
            f.write(BINARY_MAGIC)
            f.write(struct.pack("<H", BINARY_VERSION))
            f.write(struct.pack("<I", len(self.call_events)))

            # calls
            for e in self.call_events:
                f.write(struct.pack("<d", e.timestamp))
                f.write(struct.pack("<I", e.thread_id))
                f.write(struct.pack("<Q", e.source_addr))
                f.write(struct.pack("<Q", e.target_addr))
                f.write(struct.pack("<Q", e.function_context))
                f.write(b"\x00")  # call type byte
        finally:
            f.close()


def signal_handler(signum, frame):
    """Handle signals for graceful shutdown"""
    print(f"\n[!] Received signal {signum}, shutting down gracefully...")
    if hasattr(signal_handler, "tracer"):
        signal_handler.tracer.stop_tracing()
        # Don't exit here - let the main loop handle cleanup gracefully


def main():
    parser = argparse.ArgumentParser(
        description="Frida-based call tracer for monitoring function calls",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # target
    parser.add_argument("target", help="Process ID, process name, or executable path")

    # function selection
    parser.add_argument(
        "-F",
        "--hook-func",
        action="append",
        help="Function address to monitor (can be repeated)",
    )
    parser.add_argument(
        "-n",
        "--hook-name",
        action="append",
        help="Function name to monitor (can be repeated)",
    )
    parser.add_argument(
        "-r",
        "--hook-range",
        action="append",
        help="Address range to monitor (format: START:END)",
    )
    parser.add_argument(
        "-m",
        "--module",
        action="append",
        help="Module to monitor (can be repeated)",
    )
    parser.add_argument(
        "-M",
        "--monitor-all",
        action="store_true",
        help="Monitor all functions in all modules (explicit flag required)",
    )

    # output options
    parser.add_argument(
        "-o",
        "--output",
        help="Output file path (if not specified, prints summary to stdout)",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["json", "csv", "binary"],
        default="json",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--compress", action="store_true", help="Compress output file with gzip"
    )

    # control options
    parser.add_argument(
        "-t", "--timeout", type=int, help="Maximum collection time in seconds"
    )
    parser.add_argument(
        "-s",
        "--spawn",
        action="store_true",
        help="Spawn new process instead of attaching",
    )

    # device options
    parser.add_argument(
        "-D", "--device", default="local", help="Frida device (default: local)"
    )
    parser.add_argument("-H", "--host", help="Connect to remote frida-server")

    # debug options
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    # validate arguments
    if not any(
        [args.hook_func, args.hook_name, args.hook_range, args.module, args.monitor_all]
    ):
        print("[-] Error: At least one function selection option required")
        parser.print_help()
        sys.exit(1)

    # import threading only if needed
    if args.timeout:
        import threading

    # create tracer
    tracer = CallTracer(args)

    # setup signal handlers
    signal_handler.tracer = tracer
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # start tracing
    try:
        tracer.start_tracing()

        if args.output:
            print("[*] Tracing started. Press Ctrl+C to stop and save.")
        else:
            print("[*] Tracing started. Press Ctrl+C to stop and see summary.")

        # wait for completion
        if args.timeout:
            time.sleep(args.timeout + 0.5)
        else:
            # poll until interrupted or shutdown complete
            while tracer.running:
                try:
                    time.sleep(0.1)
                except KeyboardInterrupt:
                    print(f"\n[!] Interrupted by user")
                    tracer.stop_tracing()
                    break
            
            # If shutdown was initiated, wait for it to complete
            if not tracer.running and not tracer.shutdown_complete:
                print("[*] Waiting for data collection to complete...")
                # Wait for shutdown to complete (max 3 seconds)
                wait_start = time.time()
                while not tracer.shutdown_complete and (time.time() - wait_start) < 3.0:
                    time.sleep(0.01)
                
                if not tracer.shutdown_complete:
                    print("[-] Timeout waiting for shutdown, forcing cleanup...")
                    tracer._force_cleanup()

    except frida.ProcessNotFoundError:
        print(f"[-] Process not found: {args.target}")
        sys.exit(1)
    except frida.PermissionDeniedError:
        print(f"[-] Permission denied. Try with elevated privileges.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)
    finally:
        tracer.stop_tracing()

        # show results
        if tracer.call_events:
            if args.output:
                tracer.export_results()
            else:
                tracer.print_summary()
        else:
            print("[!] No calls collected.")


if __name__ == "__main__":
    main()
