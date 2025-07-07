-- module analysis demo
-- demonstrates the new module api functionality

local tracer = {}
tracer.callbacks = { "basic_block_entry" }

local logged_modules = {}
local cache_misses = 0
local cache_hits = 0

function tracer.on_basic_block_entry(vm, state, gpr, fpr)
    local pc = w1.get_reg_pc and w1.get_reg_pc(gpr) or 0
    local module_name = w1.module_get_name(pc)
    
    -- check for cache miss (unknown module) and try one rescan
    -- this handles dynamic loading where modules appear after initial scan
    if module_name == "unknown" then
        cache_misses = cache_misses + 1
        
        -- try rescanning once to detect newly loaded modules
        w1.log_info("cache miss for " .. w1.format_address(pc) .. ", rescanning modules...")
        if w1.module_scan() then
            -- try lookup again after rescan
            module_name = w1.module_get_name(pc)
            if module_name ~= "unknown" then
                w1.log_info("rescan resolved: " .. w1.format_address(pc) .. " -> " .. module_name)
            else
                w1.log_info("rescan failed to resolve " .. w1.format_address(pc))
            end
        else
            w1.log_info("rescan failed")
        end
    else
        cache_hits = cache_hits + 1
    end
    
    -- log each unique module only once
    if not logged_modules[module_name] then
        logged_modules[module_name] = true
        
        -- get full module info for detailed logging
        local module_info = w1.module_get_info(pc)
        if module_info then
            w1.log_info("discovered module: " .. module_name)
            w1.log_info("  path: " .. module_info.path)
            w1.log_info("  base: " .. w1.format_address(module_info.base_address))
            w1.log_info("  size: " .. module_info.size .. " bytes")
            w1.log_info("  type: " .. module_info.type)
            w1.log_info("  system: " .. tostring(module_info.is_system))
        else
            w1.log_info("discovered module: " .. module_name .. " (no detailed info available)")
        end
    end
    
    return w1.VMAction.CONTINUE
end

function tracer.shutdown()
    local module_count = w1.module_count()
    local unique_discovered = 0
    for _ in pairs(logged_modules) do
        unique_discovered = unique_discovered + 1
    end
    
    w1.log_info("module discovery summary:")
    w1.log_info("  total modules discovered: " .. module_count)
    w1.log_info("  unique modules executed: " .. unique_discovered)
    w1.log_info("  cache hits: " .. cache_hits)
    w1.log_info("  cache misses: " .. cache_misses)
    
    -- demonstrate module listing API
    w1.log_info("listing all discovered modules:")
    local all_modules = w1.module_list_all()
    for i, module in ipairs(all_modules) do
        if i <= 5 then  -- only show first 5 to avoid spam
            w1.log_info("  " .. i .. ". " .. module.name .. " (" .. module.type .. ")")
        end
    end
    if #all_modules > 5 then
        w1.log_info("  ... and " .. (#all_modules - 5) .. " more modules")
    end
end

return tracer