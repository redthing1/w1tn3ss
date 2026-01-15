# p1ll script guide (js)

This guide explains how to write `p1ll` patch scripts using the JS script engine (`-DWITNESS_SCRIPT_ENGINE=js`).

## intro

a `p1ll` script describes:
- what bytes to locate (signatures)
- what bytes to replace (patches)
- which platforms a patch should run on

the engine scans memory (dynamic) or a file buffer (static), builds a patch plan, and applies it.
scripts are declarative by default (via `auto_cure`) with optional imperative checks for logging and validation.

## usage

some typical commands:

```sh
# static patching (on-disk)
./build-release/p1llx -vv cure -c ./patch.js -i ./target_binary -o ./patched_binary

# dynamic patching (spawn)
./build-release/p1llx -vv poison -c ./patch.js -s ./target_binary

# dynamic patching (attach)
./build-release/p1llx -vv poison -c ./patch.js -n target_binary
```

## using `d0ct0r.py`

`scripts/d0ct0r.py` is a smart wrapper around `p1llx` to makes static patching safer.it manages backups, preserves permissions, and handles macOS codesigning.

### `auto-cure` (smart static patching)

- detect binary, backup to `<original>.d0ct0r.bak`
- patch the binary
- ad-hoc codesign on macos

```sh
./scripts/d0ct0r.py -vvv -c ./cure_script.js -i ./target_binary
```

### `insert-poison`

insert a dynamic binary load (defaulting to `p01s0n`) in the binary's imports, then resign the binary.

```sh
./scripts/d0ct0r.py -v insert-poison -i ./target_binary
```

## script contract

each script must define a top-level `cure()` function.

```js
function cure() {
  // build and apply patches
  const meta = { patches: [/* ... */] };
  return p1.auto_cure(meta);
}
```

## pattern language

p1ll signatures and patch patterns are hex strings:
- two hex digits per byte, case-insensitive
- `??` is a wildcard byte
- whitespace is ignored
- comments are allowed: `--`, `//`, `#`, `;`

Examples:

```js
const SIG = p1.sig(`
  48 8b ?? ?? ?? ?? ?? ??  // mov rax, [rip+...]
  85 c0                    // test eax, eax
  74 ??                    // je <offset>
`);

const PATCH = `
  90 90 90 90              // nop nop nop nop
`;
```

`p1.str2hex("text")` converts ascii text to a hex pattern, and `p1.hex2str("6869")` converts hex to a string. `p1.format_address(addr)` formats addresses for logging.

## api reference

### `p1.sig(pattern, options?)`

Create a signature object from a hex pattern.

Options (all optional):
- `filter` (string): regex against region/module name (dynamic). Ignored for static buffers.
- `only_executable` (bool)
- `exclude_system` (bool)
- `min_size` (int)
- `min_address` (uint64)
- `max_address` (uint64)
- `single` (bool): require exactly one match
- `max_matches` (int): cap returned matches
- `required` (bool): fail if not found (default true)
- `platforms` (array of strings): allowed platforms for this signature

Example:

```js
const SIG_CHECK = p1.sig("48 85 c0 74 ?? b0 01", {
  filter: "demo_program",
  single: true,
  required: true,
  platforms: ["windows:x64"]
});
```

### `p1.patch(signature, offset, patchPattern, options?)`

Create a patch bound to a signature. The signature must be a `p1.sig()` result.

Parameters:
- `signature`: signature object
- `offset`: signed byte offset from the match address
- `patchPattern`: hex pattern to write (wildcards keep original bytes)

Options:
- `required` (bool): fail if patch cannot be applied (default true)
- `platforms` (array of strings): allowed platforms for this patch

Example:

```js
const PATCH = p1.patch(SIG_CHECK, 0, "90 90");
```

### `p1.auto_cure(meta)`

Builds and applies a patch plan. `meta` is a recipe object.

Supported keys:
- `name` (string)
- `platforms` (array): allowed platforms for the recipe
- `validations` (array of signatures)
- `sigs` (map<string, array<signature>>): per-platform validations
- `patches` (array of patches) OR (map<string, array<patch>>)

Platform keys are strings like `windows:x64`, `linux:x64`, `darwin:arm64`, or `*` / `*:*`.

Return value:
- an apply report object with methods:
  - `get_success()`
  - `get_applied()`
  - `get_failed()`
  - `get_error_messages()`
  - `get_diagnostics()` (strings of `error_code: message`)
  - `has_errors()`

### `p1.search_sig(pattern, options?)`

Search for a single signature. Returns a `scan_result` or `null`.

`scan_result` methods:
- `get_address()`
- `get_region_name()`

If `options.single` is true and multiple matches are found, it returns `null`.

### `p1.search_sig_multiple(pattern, options?)`

Returns an array of `scan_result` entries. Useful for debugging or reporting.

### `p1.get_modules(filterPattern?)` (dynamic only)

Returns a list of modules in the target process. Each module has:
- `get_name()`
- `get_path()`
- `get_base_address()`
- `get_size()`
- `get_permissions()` (e.g., `"r-x"`)
- `get_is_system_module()`

If called in static mode, it returns an empty array.

### Logging helpers

Use these for script output:
- `p1.log_info(msg)`
- `p1.log_debug(msg)`
- `p1.log_warn(msg)`
- `p1.log_err(msg)`

## Recipe structure in depth

`auto_cure` builds a patch plan using these rules:
- `meta.platforms` gates the entire recipe.
- `sigs` are validations: all required signatures must match.
- `patches` define what is actually written.
- Each signature/patch can also have its own `platforms` and `required` flags.
- Patches are applied in address order and must not overlap.
- At least one patch entry must be produced; otherwise `auto_cure` fails with `no patch entries produced`.

If any required validation or required patch fails, `auto_cure` returns a failure report.

## examples

### 1) simple string patch

```js
const SIG_DEMO = p1.sig(p1.str2hex("DEMO VERSION"), { filter: "p1ll_test_target" });
const SIG_TRIAL = p1.sig(p1.str2hex("TRIAL VERSION"), { filter: "p1ll_test_target" });

const meta = {
  name: "string_patch",
  platforms: ["darwin:arm64", "linux:x64", "windows:x64"],
  sigs: { "*": [SIG_DEMO, SIG_TRIAL] },
  patches: {
    "*": [
      p1.patch(SIG_DEMO, 0, p1.str2hex("OOPS VERSION")),
      p1.patch(SIG_TRIAL, 0, p1.str2hex("SILLY VER"))
    ]
  }
};

function cure() {
  return p1.auto_cure(meta);
}
```

### 2) validation + targeted code patch

```js
const SIG_BANNER = p1.sig(p1.str2hex("Demo Program"), { single: true });

const SIG_CHECK = p1.sig(`
  48 85 c0        // test rax, rax
  74 ??           // je <offset>
  b0 01           // mov al, 1
`, { filter: "demo_program", single: true, platforms: ["windows:x64"] });

const FIX_CHECK = `
  ?? ?? ??        // keep test rax, rax
  90 90           // nop out the conditional jump
  ?? ??           // keep mov al, 1
`;

const meta = {
  name: "disable_license_check",
  platforms: ["windows:x64"],
  validations: [SIG_BANNER],
  patches: [p1.patch(SIG_CHECK, 0, FIX_CHECK)]
};

function cure() {
  return p1.auto_cure(meta);
}
```

### 3) patch + diagnostics

```js
const SIG_OPTIONAL = p1.sig("48 83 ec ?? 48 8d 0d ?? ?? ?? ??", {
  only_executable: true,
  required: false
});

const meta = {
  name: "optional_patch",
  patches: [p1.patch(SIG_OPTIONAL, 0, "90 90", { required: false })]
};

function cure() {
  const report = p1.auto_cure(meta);
  if (report.has_errors()) {
    p1.log_warn("optional patch had errors: " + report.get_diagnostics().join(", "));
  }
  return report;
}
```

### 4) dynamic module scanning

```js
function cure() {
  const mods = p1.get_modules("demo_program");
  mods.forEach((mod) => {
    p1.log_info(
      mod.get_name() + " @" + p1.format_address(mod.get_base_address()) + " " + mod.get_permissions()
    );
  });

  const SIG = p1.sig("e8 ?? ?? ?? ?? 48 8b c8", {
    filter: "demo_program",
    single: true
  });

  const meta = {
    name: "patch_call_site",
    patches: [p1.patch(SIG, 0, "90 90 90 90 90")]
  };

  return p1.auto_cure(meta);
}
```
