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
python call_tracer.py 1234 -F 0x401000

# trace specific functions and save to file
python call_tracer.py 1234 -F 0x401000 -F 0x402000 -o traces.json

# trace using module+offset format (handles ASLR)
python call_tracer.py 1234 -F myapp+0x1234 -F libcrypto+2048 -o traces.json

# trace by function name with symbols
python call_tracer.py myapp.exe -n malloc -n free -o calls.json

# monitor all functions in a module, excluding system modules
python call_tracer.py 1234 -m myapp --no-system -o trace.json

# monitor everything except system modules
python call_tracer.py -s ./target_binary -M --no-system -t 30

# spawn with arguments (use -- to separate)
python call_tracer.py -s ./target_binary -F 0x401000 -- --input file.txt --verbose
"""

from __future__ import print_function

import argparse
import json
import os
import signal
import sys
import time
import struct
import lzma
import threading
from dataclasses import dataclass, field
from typing import List, Tuple, Dict, Optional, Any, Set
from collections import defaultdict, Counter
from enum import Enum

import frida

# constants
VERSION = "1.0.0"
BINARY_MAGIC = b"CTRC"
BINARY_VERSION = 1
SHUTDOWN_TIMEOUT_SECONDS = 4  # max time to wait for graceful shutdown

# frida javascript agent code
js_agent_code = """
"use strict";

//=============================================================================
// CONFIGURATION AND GLOBALS
//=============================================================================

// configuration passed from python
const config = JSON.parse('CONFIG_JSON_PLACEHOLDER');
const monitoredFunctions = config.functions || [];
const targetModules = config.modules || [];
const monitorAll = config.monitorAll || false;
const excludeSystem = config.excludeSystem || false;

// state management
const threadState = new Map();           // per-thread state tracking
const functionContextStack = new Map(); // function call stack per thread
const activeStalkers = new Set();       // active stalker thread IDs

// data collection
let totalCalls = 0;
const functionStats = new Map();        // func_addr -> { calls: number, threads: Set }
const callBuffer = [];
const MAX_BUFFER_SIZE = 1000;
const FLUSH_THRESHOLD = 25;             // flush when buffer reaches this size
const FLUSH_INTERVAL_MS = 1000;         // flush every N milliseconds

//=============================================================================
// UTILITY FUNCTIONS
//=============================================================================

// periodic buffer flush
function flushBuffer() {
    try {
        if (callBuffer.length > 0) {
            const dataToSend = callBuffer.splice(0);
            console.log(`Flushing ${dataToSend.length} calls from buffer`);
            send({
                type: 'calls',
                data: dataToSend
            });
        }
    } catch (e) {
        console.error('Error flushing buffer:', e.message);
        // Clear buffer on error to prevent memory buildup
        callBuffer.length = 0;
    }
}

// force flush buffer if it's getting too large to prevent memory issues
function forceFlushIfNeeded() {
    if (callBuffer.length >= MAX_BUFFER_SIZE) {
        console.warn(`Buffer overflow protection: force flushing ${callBuffer.length} calls`);
        try {
            const dataToSend = callBuffer.splice(0);
            send({
                type: 'calls',
                data: dataToSend
            });
        } catch (e) {
            console.error('Error in force flush:', e.message);
            callBuffer.length = 0; // Clear to prevent memory buildup
        }
    }
}

// flush buffer at regular intervals
setInterval(flushBuffer, FLUSH_INTERVAL_MS);

//=============================================================================
// THREAD AND STATE MANAGEMENT
//=============================================================================

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

//=============================================================================
// EVENT PROCESSING
//=============================================================================

// process call event from stalker
function processCallEvent(sourceAddr, targetAddr, threadId, callType = 'call') {
    try {
        const funcContext = getCurrentFunctionContext(threadId);
        if (!funcContext) {
            // If no function context, this is a call happening outside our monitored functions
            // We can still record it with a generic context
            const callData = {
                timestamp: Date.now() / 1000.0,
                thread_id: threadId,
                source_addr: sourceAddr.toString(),
                target_addr: targetAddr.toString(),
                function_context: "0x0", // generic context for calls outside monitored functions
                call_type: callType
            };
            
            callBuffer.push(callData);
            totalCalls++;
            
            // check buffer size and flush if needed
            forceFlushIfNeeded();
            if (callBuffer.length >= FLUSH_THRESHOLD) {
                try {
                    const dataToSend = callBuffer.splice(0);
                    send({
                        type: 'calls',
                        data: dataToSend
                    });
                } catch (e) {
                    console.error('Error sending call data:', e.message);
                    callBuffer.length = 0;
                }
            }
            return;
        }
        
        // create call event
        const callData = {
            timestamp: Date.now() / 1000.0,
            thread_id: threadId,
            source_addr: sourceAddr.toString(),
            target_addr: targetAddr.toString(),
            function_context: funcContext,
            call_type: callType
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
        
        // check buffer size and flush if needed
        forceFlushIfNeeded();
        if (callBuffer.length >= FLUSH_THRESHOLD) {
            try {
                const dataToSend = callBuffer.splice(0);
                send({
                    type: 'calls',
                    data: dataToSend
                });
            } catch (e) {
                console.error('Error sending call data:', e.message);
                callBuffer.length = 0;
            }
        }
    } catch (e) {
        console.error('Error processing call event:', e.message);
    }
}

// process return event from stalker
function processReturnEvent(sourceAddr, threadId) {
    try {
        const funcContext = getCurrentFunctionContext(threadId);
        if (!funcContext) {
            // If no function context, still record with generic context
            const returnData = {
                timestamp: Date.now() / 1000.0,
                thread_id: threadId,
                source_addr: sourceAddr.toString(),
                target_addr: "0x0",
                function_context: "0x0",
                call_type: 'return'
            };
            
            callBuffer.push(returnData);
            totalCalls++;
            
            forceFlushIfNeeded();
            if (callBuffer.length >= FLUSH_THRESHOLD) {
                try {
                    const dataToSend = callBuffer.splice(0);
                    send({
                        type: 'calls',
                        data: dataToSend
                    });
                } catch (e) {
                    console.error('Error sending return data:', e.message);
                    callBuffer.length = 0;
                }
            }
            return;
        }
        
        // create return event
        const returnData = {
            timestamp: Date.now() / 1000.0,
            thread_id: threadId,
            source_addr: sourceAddr.toString(),
            target_addr: "0x0", // return doesn't have a target
            function_context: funcContext,
            call_type: 'return'
        };
        
        // add to buffer
        callBuffer.push(returnData);
        totalCalls++;
        
        // check buffer size and flush if needed
        forceFlushIfNeeded();
        if (callBuffer.length >= FLUSH_THRESHOLD) {
            try {
                const dataToSend = callBuffer.splice(0);
                send({
                    type: 'calls',
                    data: dataToSend
                });
            } catch (e) {
                console.error('Error sending return data:', e.message);
                callBuffer.length = 0;
            }
        }
    } catch (e) {
        console.error('Error processing return event:', e.message);
    }
}

//=============================================================================
// FUNCTION INSTRUMENTATION
//=============================================================================

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
        
        // send buffer if getting full or at regular intervals
        if (callBuffer.length >= MAX_BUFFER_SIZE || callBuffer.length >= FLUSH_THRESHOLD) {
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
                        call: true,
                        ret: true,
                        exec: false,  // Too noisy for call tracing
                        block: false, // Too noisy for call tracing
                        compile: false // Not needed for call tracing
                    },
                    onReceive: function(events) {
                        try {
                            if (!events || events.byteLength === 0) {
                                return; // Skip empty events
                            }
                            
                            const parsed = Stalker.parse(events, {
                                stringify: false,
                                annotate: false
                            });
                            
                            if (!parsed || parsed.length === 0) {
                                return; // Skip if no parsed events
                            }
                            
                            // process each event - format is [source, target, depth]
                            for (const event of parsed) {
                                try {
                                    if (!event || event.length < 3) {
                                        continue; // Skip malformed events
                                    }
                                    
                                    const sourceAddr = ptr(event[0]);
                                    const targetAddr = ptr(event[1]);
                                    const depth = event[2];
                                    
                                    if (depth >= 0) {
                                        // Positive or zero depth indicates a call
                                        processCallEvent(sourceAddr, targetAddr, threadId, 'call');
                                    } else {
                                        // Negative depth indicates a return
                                        processReturnEvent(sourceAddr, threadId);
                                    }
                                } catch (eventError) {
                                    console.error(`Error processing individual event:`, eventError.message);
                                    // Continue processing other events
                                }
                            }
                        } catch (e) {
                            console.error(`Error in stalker onReceive for thread ${threadId}:`, e.message);
                            // Don't crash the stalker, just log and continue
                        }
                    },
                    onCallSummary: function(summary) {
                        // Optional call summary logging
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
            
            // check buffer size and flush if needed
            forceFlushIfNeeded();
            if (callBuffer.length >= FLUSH_THRESHOLD) {
                try {
                    const dataToSend = callBuffer.splice(0);
                    send({
                        type: 'calls',
                        data: dataToSend
                    });
                } catch (e) {
                    console.error('Error sending exit event data:', e.message);
                    callBuffer.length = 0;
                }
            }
            
            // check if we're exiting all monitored functions in this thread
            if (depth === 1) {
                let stillInMonitoredFunction = false;
                state.depths.forEach((d, addr) => {
                    if (d > 0 && addr !== funcAddr) {
                        stillInMonitoredFunction = true;
                    }
                });
                
                if (!stillInMonitoredFunction) {
                    console.log(`Thread ${threadId} exited all monitored functions`);
                    
                    // Don't stop stalking immediately - let it continue for a bit
                    // to catch any remaining call/ret events
                    setTimeout(() => {
                        if (state.stalking) {
                            console.log(`Stopping stalker for thread ${threadId} (delayed)`);
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
                    }, 100); // Small delay to capture remaining events
                }
            }
        }
    } catch (e) {
        console.error('Error in exitMonitoredFunction:', e.message);
    }
}

//=============================================================================
// FUNCTION DISCOVERY AND HOOKING
//=============================================================================

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
            const moduleInfo = func.module ? ` in ${func.module}` : '';
            console.log(`Hooked ${func.address} (${func.name || 'unnamed'})${moduleInfo}`);
            
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

// resolve module+offset to addresses
function resolveModuleOffsets(moduleOffsets) {
    const resolved = [];
    
    moduleOffsets.forEach(entry => {
        const moduleName = entry.module;
        const offset = parseInt(entry.offset, 16);
        let found = false;
        
        // find module by name
        Process.enumerateModules().forEach(module => {
            if (found) return;
            
            // Match by exact name or basename
            const moduleBaseName = module.name.split('/').pop().split('\\\\').pop();
            if (module.name === moduleName || moduleBaseName === moduleName) {
                const baseAddr = module.base;
                const targetAddr = baseAddr.add(offset);
                
                resolved.push({
                    address: targetAddr.toString(),
                    name: `${moduleName}+${entry.offset}`,
                    module: module.name,
                    offset: entry.offset
                });
                found = true;
                console.log(`Resolved ${moduleName}+${entry.offset} to ${targetAddr} (base: ${baseAddr})`);
            }
        });
        
        if (!found) {
            console.warn(`Could not resolve module: ${moduleName}`);
        }
    });
    
    return resolved;
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

// check if a module is a system module
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

// discover functions in specified modules
function discoverModuleFunctions(moduleNames) {
    const functions = [];
    
    Process.enumerateModules().forEach(module => {
        // Skip system modules if excludeSystem is enabled
        if (excludeSystem && isSystemModule(module.name, module.path)) {
            return;
        }
        
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
    
    const moduleDesc = moduleNames.length > 0 ? moduleNames.join(', ') : 'all modules';
    const systemDesc = excludeSystem ? ' (excluding system modules)' : '';
    console.log(`Discovered ${functions.length} functions in ${moduleDesc}${systemDesc}`);
    return functions;
}

// discover all functions in all modules (for monitor-all mode)
function discoverAllFunctions() {
    const functions = [];
    
    Process.enumerateModules().forEach(module => {
        // Skip system modules if excludeSystem is enabled
        if (excludeSystem && isSystemModule(module.name, module.path)) {
            console.log(`Skipping system module: ${module.name}`);
            return;
        }
        
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
    
    const systemDesc = excludeSystem ? ' (excluding system modules)' : '';
    console.log(`Discovered ${functions.length} total functions in all modules${systemDesc}`);
    return functions;
}

//=============================================================================
// CLEANUP AND SHUTDOWN
//=============================================================================

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
    
    // ensure completion signal is sent
    console.log('Sending process complete signal...');
    send({ type: 'process_complete' });
}

//=============================================================================
// INITIALIZATION AND SETUP
//=============================================================================

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

// process module+offset entries if any
const moduleOffsets = monitoredFunctions.filter(f => f.module && f.offset);
if (moduleOffsets.length > 0) {
    const resolved = resolveModuleOffsets(moduleOffsets);
    resolved.forEach(r => monitoredFunctions.push(r));
}

// process function names if any
const namesToResolve = monitoredFunctions.filter(f => f.name && !f.address && !f.module).map(f => f.name);
if (namesToResolve.length > 0) {
    const resolved = resolveFunctionNames(namesToResolve);
    resolved.forEach(r => monitoredFunctions.push(r));
}

// filter out functions without addresses
const validFunctions = monitoredFunctions.filter(f => f.address);

// update monitored functions list
monitoredFunctions.length = 0;
validFunctions.forEach(f => monitoredFunctions.push(f));

// initialize function statistics for all monitored functions
monitoredFunctions.forEach(func => {
    functionStats.set(func.address, { calls: 0, threads: new Set() });
});

// setup hooks
if (monitoredFunctions.length > 0) {
    setupFunctionHooks();
} else {
    send({
        type: 'error',
        message: 'No valid functions to monitor'
    });
}

//=============================================================================
// MESSAGE HANDLING AND LIFECYCLE
//=============================================================================

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

// collect module information early for RE analysis
const moduleInfo = [];
Process.enumerateModules().forEach(module => {
    moduleInfo.push({
        name: module.name,
        base: module.base.toString(),
        size: module.size,
        path: module.path
    });
});

// send module information 
send({
    type: 'modules',
    data: moduleInfo
});

// send ready signal
send({ type: 'ready' });
"""


# ==============================================================================
# DATA STRUCTURES
# ==============================================================================


@dataclass
class CallEvent:
    """Represents a single call/return event"""

    timestamp: float
    thread_id: int
    source_addr: int
    target_addr: int
    function_context: int
    call_type: str


@dataclass
class FunctionContext:
    """Tracks statistics for a monitored function"""

    address: int
    name: Optional[str]
    module: Optional[str] = None
    total_calls: int = 0
    unique_threads: Set[int] = field(default_factory=set)
    unique_targets: Set[int] = field(default_factory=set)


@dataclass
class CallSummary:
    """Summary statistics for a tracing session"""

    total_calls: int
    unique_threads: int
    duration: float
    calls_per_second: float
    functions: List[Dict[str, Any]]
    top_targets: List[Tuple[str, int]]
    thread_distribution: Dict[int, int]


# ==============================================================================
# MAIN TRACER CLASS
# ==============================================================================


class CallTracer:
    """Main call tracer implementation using Frida"""

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
        self.modules = []  # module information for RE analysis

        # prepare monitored functions
        self._prepare_monitored_functions()

    # --------------------------------------------------------------------------
    # Setup and Configuration
    # --------------------------------------------------------------------------

    def _prepare_monitored_functions(self):
        """Prepare the list of functions to monitor"""
        functions = []

        # add functions by address or module+offset
        for addr in self.args.hook_func or []:
            try:
                # Check for module+offset format (e.g., "mymodule+1234" or "mymodule+0x1234")
                if "+" in addr:
                    module_name, offset_str = addr.split("+", 1)
                    # Parse offset as hex (strip 0x prefix if present)
                    offset_clean = (
                        offset_str[2:]
                        if offset_str.startswith(("0x", "0X"))
                        else offset_str
                    )
                    offset = int(offset_clean, 16)
                    functions.append(
                        {
                            "module": module_name.strip(),
                            "offset": hex(offset),
                            "name": f"{module_name}+{hex(offset)}",
                        }
                    )
                else:
                    # Handle regular address format - always treat as hex
                    if addr.startswith(("0x", "0X")):
                        addr_int = int(addr, 16)
                    else:
                        # Always treat as hex, even without 0x prefix
                        addr_int = int(addr, 16)
                    func_ctx = FunctionContext(address=addr_int, name=None)
                    self.function_contexts[addr] = func_ctx
                    functions.append({"address": addr, "name": None})
            except ValueError:
                print(
                    f"[-] Invalid address/module+offset format: {addr}. "
                    f"Use hex (0x1234 or 1234) or module+offset (mymodule+0x1234)."
                )
                sys.exit(1)

        # add functions by name
        for name in self.args.hook_name or []:
            functions.append({"address": None, "name": name})

        # add address ranges
        for range_str in self.args.hook_range or []:
            if ":" not in range_str:
                print(f"[-] Invalid range format: {range_str}. Use START:END format.")
                sys.exit(1)
            try:
                start_str, end_str = range_str.split(":", 1)
                # Validate that both parts are valid addresses
                start_addr = (
                    int(start_str, 16)
                    if start_str.startswith("0x")
                    else int(start_str, 16)
                )
                end_addr = (
                    int(end_str, 16) if end_str.startswith("0x") else int(end_str, 16)
                )
                if start_addr >= end_addr:
                    print(
                        f"[-] Invalid range: start address must be less than end address"
                    )
                    sys.exit(1)
                functions.append({"range": range_str})
            except ValueError:
                print(
                    f"[-] Invalid range format: {range_str}. Use hex addresses like 0x1000:0x2000"
                )
                sys.exit(1)

        self.monitored_functions = functions

    def _resolve_address_to_module_offset(self, address):
        """Resolve an address to module+offset format"""
        if not self.modules:
            # handle both int and string addresses
            if isinstance(address, str):
                return address if address.startswith("0x") else f"0x{address}"
            return hex(address)  # fallback to hex if no modules

        # handle different address formats
        if isinstance(address, str):
            if address.startswith("0x"):
                addr_int = int(address, 16)
            elif address.isdigit():
                addr_int = int(address)
            else:
                try:
                    addr_int = int(address, 16)
                except ValueError:
                    return address  # return as-is if can't parse
        else:
            addr_int = address

        # Find the module containing this address
        for module in self.modules:
            base_addr = int(module["base"], 16)
            module_size = module["size"]

            if base_addr <= addr_int < (base_addr + module_size):
                offset = addr_int - base_addr
                return f"{module['name']}+{hex(offset)}"

        # If no module found, return hex address
        return hex(addr_int)

    def start_tracing(self):
        """Start the tracing session"""
        try:
            # setup device
            self.device = self._get_device()

            # attach or spawn
            if self.args.spawn:
                if not os.path.exists(self.args.target):
                    raise FileNotFoundError(
                        f"Target binary not found: {self.args.target}"
                    )

                # prepare spawn options
                spawn_options = {}
                if self.args.disable_aslr:
                    # disable aslr using frida
                    spawn_options["aslr"] = "disable"
                    # on macos, try DYLD_DISABLE_ASLR
                    if sys.platform == "darwin":
                        spawn_options["env"] = {
                            "DYLD_DISABLE_ASLR": "1",
                        }
                    print("[*] Attempting to disable ASLR for the target process")

                # Build command line with target and arguments
                cmd_line = [self.args.target] + self.args.target_args
                if self.args.target_args:
                    print(f"[*] Spawning with arguments: {' '.join(cmd_line)}")
                self.pid = self.device.spawn(cmd_line, **spawn_options)
                self.session = self.device.attach(self.pid)
                print(f"[+] Spawned process with PID: {self.pid}")
            else:
                # attach to existing process
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
                                if target.lower() in p.name.lower()
                                or str(p.pid) == target
                            ]

                            if not matches:
                                available_processes = [
                                    f"{p.pid}: {p.name}" for p in processes[:10]
                                ]
                                available_str = "\n".join(available_processes)
                                if len(processes) > 10:
                                    available_str += f"\n... and {len(processes) - 10} more processes"

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

            # validate we have something to monitor
            if (
                not self.monitored_functions
                and not self.args.module
                and not self.args.monitor_all
            ):
                raise ValueError(
                    "No functions, modules, or monitor-all specified. "
                    "Use -F/--hook-func, -n/--hook-name, -m/--module, or -M/--monitor-all"
                )

            # prepare configuration for JS agent
            config = {
                "functions": self.monitored_functions,
                "modules": self.args.module or [],
                "monitorAll": self.args.monitor_all,
                "excludeSystem": self.args.no_system,
            }

            # inject script with properly escaped JSON
            try:
                # properly escape JSON for JavaScript string literal
                config_json = json.dumps(config)
                # escape single quotes and backslashes for JavaScript string literal
                config_json_escaped = config_json.replace("\\", "\\\\").replace(
                    "'", "\\'"
                )
                script_code = js_agent_code.replace(
                    "CONFIG_JSON_PLACEHOLDER", config_json_escaped
                )

                self.script = self.session.create_script(script_code)
                self.script.on("message", self._on_message)
                self.script.load()

            except frida.InvalidArgumentError as e:
                raise RuntimeError(f"Invalid JavaScript agent code: {e}")
            except Exception as e:
                raise RuntimeError(
                    f"Failed to inject JavaScript agent: {e}. Check target process compatibility."
                )

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

    # --------------------------------------------------------------------------
    # Message Handling
    # --------------------------------------------------------------------------

    def _on_message(self, message, data):
        """Handle messages from the JS agent"""
        try:
            if not message or not isinstance(message, dict):
                print(f"[!] Invalid message format: {message}")
                return

            if message["type"] == "error":
                print(f"[!] Script error: {message}")
                return

            if message["type"] == "send":
                payload = message.get("payload", {})
                if not isinstance(payload, dict):
                    print(f"[!] Invalid payload format: {payload}")
                    return

                msg_type = payload.get("type")

            if msg_type == "ready":
                print("[+] Agent ready and monitoring")

            elif msg_type == "modules":
                # store module information for RE analysis
                self.modules = payload.get("data", [])
                print(f"[*] Collected information for {len(self.modules)} modules")

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
                if self.args.verbose:
                    print(f"[DEBUG] Setting shutdown_complete=True, running=False")
                self.shutdown_complete = True
                self.running = False  # Stop the main loop

            elif msg_type == "error":
                print(f"[!] Error: {payload.get('message', 'Unknown error')}")

        except KeyError as e:
            print(f"[!] Missing required field in message: {e}")
        except Exception as e:
            print(f"[!] Error processing message: {e}")
            if self.args.verbose:
                import traceback

                traceback.print_exc()

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

    # --------------------------------------------------------------------------
    # Data Analysis and Export
    # --------------------------------------------------------------------------

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
            print("-" * 70)
            for call_type, count in sorted(call_types.items()):
                print(f"{call_type:<12}: {count:>8,}")

        if summary.functions:
            print(f"\nMonitored Functions ({len(summary.functions)}):")
            print("-" * 70)
            print(
                f"{'Module+Offset':<36} {'Name':<36} {'Calls':>16} {'Threads':>8} {'Targets':>8}"
            )
            print("-" * 70)
            for func in summary.functions:
                name = func["name"][:20]
                # Convert address to module+offset for display
                module_offset = self._resolve_address_to_module_offset(func["address"])
                print(
                    f"{module_offset:<36} {name:<36} {func['calls']:>16,} "
                    f"{func['threads']:>8} {func['unique_targets']:>8}"
                )

        if summary.top_targets:
            print(f"\nTop Call Targets:")
            print("-" * 70)
            print(f"{'Module+Offset':<36} {'Count':>16}")
            print("-" * 70)
            for addr, count in summary.top_targets:
                # Convert hex address to module+offset for display
                module_offset = self._resolve_address_to_module_offset(addr)
                print(f"{module_offset:<36} {count:>16,}")

        if len(summary.thread_distribution) > 1:
            print(f"\nThread Distribution:")
            print("-" * 70)
            sorted_threads = sorted(
                summary.thread_distribution.items(), key=lambda x: x[1], reverse=True
            )
            for tid, count in sorted_threads[:5]:
                pct = (count / summary.total_calls) * 100
                print(f"Thread {tid:<8}: {count:>8,} calls ({pct:>5.1f}%)")
            if len(sorted_threads) > 5:
                print(f"... and {len(sorted_threads) - 5} more threads")

        print("\n" + "=" * 70)

    def export_results(self):
        """Export results to file"""
        try:
            output_file = self.args.output
            if not output_file:
                raise ValueError("No output file specified")

            # Validate output directory exists
            output_dir = os.path.dirname(os.path.abspath(output_file))
            if not os.path.exists(output_dir):
                os.makedirs(output_dir, exist_ok=True)
                print(f"[*] Created output directory: {output_dir}")

            # handle compression
            if self.args.compress:
                if not output_file.endswith(".xz"):
                    output_file += ".xz"

            # export based on format
            if self.args.format == "json":
                self._export_json(output_file)
            else:
                raise ValueError(f"Unsupported export format: {self.args.format}")

            if os.path.exists(output_file):
                file_size = os.path.getsize(output_file)
                print(f"[+] Results saved to: {output_file} ({file_size:,} bytes)")
            else:
                print(f"[!] Warning: Output file was not created: {output_file}")

        except Exception as e:
            print(f"[!] Error exporting results: {e}")
            if self.args.verbose:
                import traceback

                traceback.print_exc()
            raise

    def _export_json(self, filepath):
        """Export to JSON format"""
        try:
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
                "modules": self.modules,
                "calls": [
                    {
                        "timestamp": e.timestamp,
                        "thread_id": e.thread_id,
                        "source_addr": hex(e.source_addr) if e.source_addr else "0x0",
                        "source_module_offset": (
                            self._resolve_address_to_module_offset(e.source_addr)
                            if e.source_addr
                            else "0x0"
                        ),
                        "target_addr": hex(e.target_addr) if e.target_addr else "0x0",
                        "target_module_offset": (
                            self._resolve_address_to_module_offset(e.target_addr)
                            if e.target_addr
                            else "0x0"
                        ),
                        "function_context": (
                            hex(e.function_context) if e.function_context else "0x0"
                        ),
                        "function_context_module_offset": (
                            self._resolve_address_to_module_offset(e.function_context)
                            if e.function_context
                            else "0x0"
                        ),
                        "call_type": e.call_type or "unknown",
                    }
                    for e in self.call_events
                ],
            }

            if self.args.compress:
                with lzma.open(filepath, "wt", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
            else:
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)

        except (IOError, OSError) as e:
            raise RuntimeError(f"Failed to write JSON file: {e}")
        except Exception as e:
            raise RuntimeError(f"Error creating JSON data: {e}")


# ==============================================================================
# SIGNAL HANDLING AND MAIN FUNCTION
# ==============================================================================


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
        help="Function address or module+offset to monitor (can be repeated).\n"
        "Examples: 0x401000, 401000, mymodule+0x1234, mymodule+1234",
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
    parser.add_argument(
        "--no-system",
        action="store_true",
        help="Exclude system modules from monitoring",
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
        choices=["json"],
        default="json",
        help="Output format",
    )
    parser.add_argument(
        "--compress", action="store_true", help="Compress output file with XZ/LZMA"
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
    parser.add_argument(
        "--disable-aslr",
        action="store_true",
        help="Disable ASLR for spawned process (macOS only, requires code signing)",
    )

    # device options
    parser.add_argument(
        "-D", "--device", default="local", help="Frida device (default: local)"
    )
    parser.add_argument("-H", "--host", help="Connect to remote frida-server")

    # debug options
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    # target arguments (after --)
    parser.add_argument(
        "target_args", nargs="*", 
        help="Arguments to pass to spawned process (use after --)"
    )

    args = parser.parse_args()

    # validate arguments
    if not any(
        [args.hook_func, args.hook_name, args.hook_range, args.module, args.monitor_all]
    ):
        print("[-] Error: At least one function selection option required")
        parser.print_help()
        sys.exit(1)

    # threading is already imported at module level

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
                    if args.verbose:
                        print(
                            f"[DEBUG] Main loop: running={tracer.running}, shutdown_complete={tracer.shutdown_complete}"
                        )

                    # Check if spawned process has exited
                    if args.spawn and tracer.pid:
                        try:
                            processes = tracer.device.enumerate_processes()
                            process_exists = any(p.pid == tracer.pid for p in processes)
                            if not process_exists:
                                print("[*] Spawned process has exited")
                                tracer.running = False
                                break
                        except Exception as e:
                            if args.verbose:
                                print(f"[DEBUG] Error checking process existence: {e}")
                            # If we can't enumerate processes, assume it's still running
                            pass

                except KeyboardInterrupt:
                    print(f"\n[!] Interrupted by user")
                    tracer.stop_tracing()
                    break

            print(
                f"[*] Main loop exited: running={tracer.running}, shutdown_complete={tracer.shutdown_complete}"
            )

            # If shutdown was initiated, wait for it to complete
            if not tracer.running and not tracer.shutdown_complete:
                print("[*] Waiting for data collection to complete...")
                # Wait for shutdown to complete
                wait_start = time.time()
                while (
                    not tracer.shutdown_complete
                    and (time.time() - wait_start) < SHUTDOWN_TIMEOUT_SECONDS
                ):
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
            tracer.stop_tracing()

            # show results
            tracer.print_summary()

            # export results if requested
            if tracer.call_events:
                if args.output:
                    print(f"[*] Exporting results to {args.output}...")
                    tracer.export_results()
            else:
                print("[!] No calls collected.")
        except Exception as e:
            print(f"[-] Error during cleanup: {e}")
            if args.verbose:
                import traceback

                traceback.print_exc()


if __name__ == "__main__":
    main()
