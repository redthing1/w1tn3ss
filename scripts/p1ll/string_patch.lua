-- some sample signatures with region filters
local SIG_DEMO_VERSION = p1.sig(p1.str2hex("DEMO VERSION"), {filter = "p1ll_test_target"})
local SIG_TRIAL_VERSION = p1.sig(p1.str2hex("TRIAL VERSION"), {filter = "p1ll_test_target"})

local meta = {
    name = "string_patch",
    -- supported platforms
    platforms = {"darwin:arm64", "linux:x64", "windows:x64"},

    -- all matching sigs must match in order for cure to be applicable
    sigs = {
        -- wildcards match all platforms
        ["*"] = {SIG_DEMO_VERSION, SIG_TRIAL_VERSION}
    },

    -- patches to apply if all sigs match
    patches = {
        -- wildcard patches are used on all platforms
        ["*"] = { -- a patch declares a signature, an offset, a replacement, and optional parameters
        p1.patch(SIG_DEMO_VERSION, 0, p1.str2hex("FULL VERSION")), 
        p1.patch(SIG_TRIAL_VERSION, 0, p1.str2hex("LICENSED VER"))}
    }
}

-- the cure function is called by the p1ll framework
function cure()
    -- use the mostly declarative auto cure api
    return p1.auto_cure(meta)
end
