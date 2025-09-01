-- darwin api monitoring demo
-- demonstrates real-time api tracing with semantic analysis on darwin
-- requires: DYLD_SHARED_CACHE_DUMP_DIR=/tmp/libraries for symbol resolution
local tracer = {}

-- statistics tracking
local stats = {
    total_calls = 0,
    by_category = {},
    by_module = {}
}

-- initialize api monitoring callbacks
function tracer.init()
    w1.log_info("initializing darwin api monitor")

    -- monitor printf with detailed argument analysis
    tracer.register_api_symbol_callback("libsystem_c.dylib", "_printf", function(event)
        if event.type == "call" then
            w1.log_info(string.format("[printf] called from %s -> %s", w1.format_address(event.source_address),
                w1.format_address(event.target_address)))

            -- show arguments if available
            if #event.arguments > 0 then
                for i, arg in ipairs(event.arguments) do
                    w1.log_info(string.format("  arg[%d] %s: %s (%s)", i, arg.param_name or "param",
                        arg.interpreted_value, arg.is_pointer and "ptr" or "val"))
                end
            end
        elseif event.type == "return" then
            if event.return_value then
                w1.log_info(string.format("[printf] returned: %s", event.return_value.interpreted_value))
            end
        end
    end)

    tracer.register_api_symbol_callback("libsystem_c.dylib", "_puts", function(event)
        if event.type == "call" then
            w1.log_info("[stdio] " .. event.formatted_call)
        end
    end)

    -- monitor heap operations with allocation tracking
    local allocations = {}
    tracer.register_api_category_callback(w1.API_CATEGORY.HEAP_MANAGEMENT, function(event)
        if event.type == "call" then
            if event.symbol_name == "_malloc" then
                local size = event.arguments[1] and event.arguments[1].raw_value or 0
                w1.log_info(string.format("[heap] malloc(%d bytes)", size))
            elseif event.symbol_name == "_free" then
                local ptr = event.arguments[1] and event.arguments[1].interpreted_value or "null"
                w1.log_info(string.format("[heap] free(%s)", ptr))
            elseif event.symbol_name == "_calloc" then
                local count = event.arguments[1] and event.arguments[1].raw_value or 0
                local size = event.arguments[2] and event.arguments[2].raw_value or 0
                w1.log_info(string.format("[heap] calloc(%d, %d) = %d bytes", count, size, count * size))
            end
        elseif event.type == "return" and event.symbol_name == "_malloc" then
            if event.return_value then
                local ptr = event.return_value.interpreted_value
                local size = event.arguments[1] and event.arguments[1].raw_value or 0
                allocations[ptr] = size
                w1.log_info(string.format("[heap] malloc returned %s", ptr))
            end
        end
    end)

    -- monitor file operations
    tracer.register_api_category_callback(w1.API_CATEGORY.FILE_IO, function(event)
        if event.type == "call" then
            w1.log_info(string.format("[file] %s", event.formatted_call))
        end
    end)

    -- monitor string operations (often security-relevant)
    tracer.register_api_symbol_callback("libsystem_c.dylib", "_strcpy", function(event)
        if event.type == "call" then
            w1.log_info(string.format("[string] %s (unsafe)", event.formatted_call))
        end
    end)

    tracer.register_api_symbol_callback("libsystem_c.dylib", "_strncpy", function(event)
        if event.type == "call" then
            w1.log_info(string.format("[string] %s", event.formatted_call))
        end
    end)

    -- generic api tracking for statistics
    tracer.register_api_module_callback("libsystem_c.dylib", track_api_call)
    tracer.register_api_module_callback("libsystem_malloc.dylib", track_api_call)
    tracer.register_api_module_callback("libsystem_kernel.dylib", track_api_call)
end

-- track api calls for statistics
function track_api_call(event)
    if event.type == "call" then
        stats.total_calls = stats.total_calls + 1

        -- track by category using the built-in utility
        local cat_name = w1.api_category_name(event.category)
        stats.by_category[cat_name] = (stats.by_category[cat_name] or 0) + 1

        -- track by module
        stats.by_module[event.module_name] = (stats.by_module[event.module_name] or 0) + 1
    end
end

-- api monitoring works by intercepting execution transfers (calls and returns)
-- the w1script engine automatically detects these callback functions
function tracer.on_exec_transfer_call(vm, state, gpr, fpr)
    -- the actual api analysis happens automatically in the c++ layer
    -- when execution transfers are detected. we just need this callback
    -- to enable qbdi's transfer detection instrumentation.
    return w1.VMAction.CONTINUE
end

function tracer.on_exec_transfer_return(vm, state, gpr, fpr)
    -- same as above - enables detection of function returns
    return w1.VMAction.CONTINUE
end

-- summary on shutdown
function tracer.shutdown()
    w1.log_info("")
    w1.log_info("=== api monitoring summary ===")
    w1.log_info("total api calls: " .. stats.total_calls)

    if next(stats.by_category) then
        w1.log_info("")
        w1.log_info("calls by category:")
        for cat, count in pairs(stats.by_category) do
            w1.log_info(string.format("  %-12s: %d", cat, count))
        end
    end

    if next(stats.by_module) then
        w1.log_info("")
        w1.log_info("calls by module:")
        for mod, count in pairs(stats.by_module) do
            w1.log_info(string.format("  %-30s: %d", mod, count))
        end
    end
end

return tracer
