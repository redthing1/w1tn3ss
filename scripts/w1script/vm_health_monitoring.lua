-- w1script vm health monitoring
-- comprehensive vm status checking and health reporting

local instruction_count = 0
local health_checks = {}

-- comprehensive vm health assessment
local function perform_health_check()
    w1.log_info("=== vm health monitor ===")
    
    local health_report = {
        timestamp = w1.get_timestamp(),
        status = "unknown",
        metrics = {},
        warnings = {},
        errors = {}
    }
    
    -- check basic api accessibility
    if w1.log_info then
        health_report.metrics.logging_accessible = true
        w1.log_info("logging system accessible")
    else
        health_report.metrics.logging_accessible = false
        table.insert(health_report.errors, "logging system not accessible")
    end
    
    -- check register access functions
    if w1.get_reg_pc then
        health_report.metrics.register_access_available = true
        w1.log_info("register access functions available")
    else
        health_report.metrics.register_access_available = false
        table.insert(health_report.warnings, "register access functions not available")
    end
    
    -- check memory analysis functions
    if w1.getCurrentProcessMaps then
        health_report.metrics.memory_analysis_available = true
        w1.log_info("memory analysis functions available")
    else
        health_report.metrics.memory_analysis_available = false
        table.insert(health_report.warnings, "memory analysis functions not available")
    end
    
    -- check utility functions
    local utility_check = 0
    local utilities = {"to_json", "format_address", "write_file", "get_timestamp"}
    for _, util in ipairs(utilities) do
        if w1[util] then
            utility_check = utility_check + 1
        end
    end
    
    health_report.metrics.utility_functions = utility_check
    health_report.metrics.utility_coverage = utility_check / #utilities
    
    if utility_check == #utilities then
        w1.log_info("all utility functions available")
    else
        table.insert(health_report.warnings, "some utility functions missing: " .. utility_check .. "/" .. #utilities)
    end
    
    -- check callback system
    if w1.VMAction and w1.VMAction.CONTINUE then
        health_report.metrics.callback_system_available = true
        w1.log_info("callback system available")
    else
        health_report.metrics.callback_system_available = false
        table.insert(health_report.errors, "callback system not available")
    end
    
    -- overall health assessment
    local error_count = #health_report.errors
    local warning_count = #health_report.warnings
    
    if error_count == 0 and warning_count == 0 then
        health_report.status = "healthy"
        w1.log_info("vm status: healthy")
    elseif error_count == 0 and warning_count > 0 then
        health_report.status = "warning"
        w1.log_info("vm status: warning (" .. warning_count .. " warnings)")
    else
        health_report.status = "error"
        w1.log_error("vm status: error (" .. error_count .. " errors, " .. warning_count .. " warnings)")
    end
    
    -- detailed reporting
    if #health_report.warnings > 0 then
        w1.log_info("warnings:")
        for _, warning in ipairs(health_report.warnings) do
            w1.log_info("  - " .. warning)
        end
    end
    
    if #health_report.errors > 0 then
        w1.log_error("errors:")
        for _, error in ipairs(health_report.errors) do
            w1.log_error("  - " .. error)
        end
    end
    
    return health_report
end

local tracer = {}
tracer.callbacks = { "instruction_postinst" }

function tracer.on_instruction_postinst(vm, gpr, fpr)
    instruction_count = instruction_count + 1
    
    -- perform health checks at regular intervals
    if instruction_count % 5000 == 0 then
        local check_result = perform_health_check()
        table.insert(health_checks, check_result)
        w1.log_info("health check #" .. #health_checks .. " completed - status: " .. check_result.status)
    end
    
    return w1.VMAction.CONTINUE
end

function tracer.shutdown()
    w1.log_info("=== vm health monitoring summary ===")
    w1.log_info("total instructions traced: " .. instruction_count)
    w1.log_info("health checks performed: " .. #health_checks)
    
    -- perform final comprehensive health check
    local final_health = perform_health_check()
    table.insert(health_checks, final_health)
    
    -- analyze health trends
    local healthy_count = 0
    local warning_count = 0
    local error_count = 0
    
    for _, check in ipairs(health_checks) do
        if check.status == "healthy" then
            healthy_count = healthy_count + 1
        elseif check.status == "warning" then
            warning_count = warning_count + 1
        else
            error_count = error_count + 1
        end
    end
    
    w1.log_info("health summary:")
    w1.log_info("  healthy checks: " .. healthy_count)
    w1.log_info("  warning checks: " .. warning_count)
    w1.log_info("  error checks: " .. error_count)
    
    -- export comprehensive health report
    local results = {
        timestamp = w1.get_timestamp(),
        instructions = instruction_count,
        health_checks = health_checks,
        summary = {
            total_checks = #health_checks,
            healthy = healthy_count,
            warnings = warning_count,
            errors = error_count
        },
        final_status = final_health.status,
        demonstration = "vm health monitoring"
    }
    
    local json_output = w1.to_json(results)
    w1.log_info("comprehensive health report: " .. json_output)
    
    if w1.write_file("/tmp/w1script_health_monitoring.json", json_output) then
        w1.log_info("exported health report to /tmp/w1script_health_monitoring.json")
    end
    
    w1.log_info("vm health monitoring completed")
end

return tracer