# Linux Injection Techniques in w1nj3ct

This document provides a detailed technical description of the library injection techniques used for the Linux platform within the `w1nj3ct` framework. Two primary methods are supported: **Runtime Injection** via `ptrace` and **Launch-time Injection** via the `LD_PRELOAD` environment variable.

---

## 1. Runtime Injection via `ptrace`

This method injects a shared object (`.so`) into a process that is already running. It is a powerful but complex technique that relies on the `ptrace` system call to manipulate and control the target process.

### Core Concept

The `ptrace` (process trace) system call provides a mechanism for a parent process to observe and control the execution of another process (the "tracee"). It allows the tracer to read and write to the tracee's memory and registers, and to intercept signals and system calls. This level of control is leveraged to force the target process to execute a call to `dlopen()`, effectively loading the desired shared library into its own address space.

### Step-by-Step Process

The injection sequence is a carefully orchestrated series of `ptrace` calls and memory manipulations:

1.  **Attach to Target**: The injector first attaches to the target process using `ptrace(PTRACE_ATTACH, pid, NULL, NULL)`. This sends a `SIGSTOP` to the target, pausing its execution and making it a tracee of the injector. The injector then waits for the process to stop using `waitpid()`.

2.  **Discover C Library Functions**: To call `dlopen`, the injector must know its address within the target's virtual memory.
    *   It reads `/proc/[pid]/maps` to find the base address of the C library (`libc.so.6` for glibc, or `ld-musl-*.so.1` for musl).
    *   It then opens and parses this ELF (Executable and Linkable Format) file to find the offsets of the required symbols: `dlopen`, `dlclose`, `dlsym`, and `dlerror`. On older glibc versions, internal symbols like `__libc_dlopen_mode` are used.
    *   The final virtual address is calculated by adding the library's base address (from `/proc/[pid]/maps`) to the symbol's offset (from the ELF file).

3.  **Save Original State**: The injector saves the target's current register values using `ptrace(PTRACE_GETREGS, ...)` and backs up the small section of code at the target's instruction pointer that will be overwritten. This is crucial for restoring the process to its original state later.

4.  **Allocate Memory in Target**: The injector needs a place to write the path of the library to be injected. It hijacks the target process to make a `mmap` system call.
    *   The registers are configured for the `mmap` syscall (`rax` holds the syscall number, other registers hold arguments like size, protection flags, etc.).
    *   A `syscall` instruction followed by a `trap` (`int3`) instruction is written to the target's instruction pointer address.
    *   The injector continues the process, which executes the `mmap` call and then hits the trap.
    *   The return value of `mmap` (the address of the newly allocated memory) is read from the `rax` register.

5.  **Write Library Path**: The absolute path of the shared library to be injected is written into the newly allocated memory region using `ptrace(PTRACE_POKEDATA, ...)`.

6.  **Execute `dlopen`**: The core of the injection occurs here.
    *   The registers are set up for a function call. The instruction pointer (`rip` on x86-64) is set to the address of `dlopen` discovered in step 2.
    *   The first argument register (`rdi` on x86-64) is set to the address of the library path (written in step 5). The second argument (`rsi`) is set to the `dlopen` flags (e.g., `RTLD_LAZY`).
    *   A `call` instruction followed by a `trap` is written to the instruction pointer.
    *   The process is continued. It executes the `dlopen` call and stops at the trap.

7.  **Retrieve Handle & Cleanup**:
    *   The return value of `dlopen` (the library handle) is retrieved from the return value register (`rax`). If it's `NULL`, `dlerror` is called in a similar fashion to get the error message.
    *   The original code that was overwritten is restored using `ptrace(PTRACE_POKEDATA, ...)`.
    *   The original register values are restored using `ptrace(PTRACE_SETREGS, ...)`.

8.  **Detach**: The injector detaches from the target using `ptrace(PTRACE_DETACH, ...)`, which allows the target process to resume its normal execution, now with the new library loaded.

### Requirements and Hurdles

*   **Permissions**: This is the most common obstacle.
    *   **Root Privileges**: Running the injector as `root` typically bypasses most permission checks.
    *   **Ptrace Scope**: The `kernel.yama.ptrace_scope` sysctl setting is a primary security control. If set to `1` (the default on many systems), a process can only be traced by its direct parent, preventing arbitrary process injection. This must be set to `0` for same-user, non-parent tracing.
*   **Target State**: The target process is interrupted at an arbitrary point. If it is inside a non-reentrant function (like `malloc`), and the injected call to `dlopen` also uses that function, the process will deadlock.
*   **Seccomp**: Security profiles using `seccomp` can block the `ptrace` system call, making injection impossible.

---

## 2. Launch-time Injection via `LD_PRELOAD`

This method is simpler and less invasive. It launches a new process from a specified binary and uses a standard feature of the dynamic linker to load a library at startup.

### Core Concept

`LD_PRELOAD` is an environment variable that contains a list of user-specified shared libraries for the dynamic linker (`ld.so`) to load *before* any other library, including the standard C library. By setting this variable to the path of our library, we ensure it is loaded into the process's address space as soon as it starts.

### Step-by-Step Process

1.  **Environment Setup**: The injector prepares a new environment for the child process. It typically starts by inheriting the environment of the injector process.

2.  **Set `LD_PRELOAD`**: The `LD_PRELOAD` environment variable is added to this new environment, with its value set to the absolute path of the shared library to be injected. Any other user-specified environment variables are also set at this time.

3.  **Fork and Exec**:
    *   The injector calls `fork()` to create a new child process.
    *   The child process then calls `execve()`, passing it the path to the target binary, the command-line arguments, and the newly constructed environment.
    *   The operating system's kernel, in conjunction with the dynamic linker, processes the `execve` call. The dynamic linker sees the `LD_PRELOAD` variable and loads the specified library, calling its constructors before the target binary's `main` function is ever executed.

4.  **Wait for Completion**: The parent process (the injector) waits for the child process to terminate using `waitpid()` and reports its exit status.

### Requirements and Hurdles

*   **Dynamic Linking**: This method only works for dynamically linked executables. It has no effect on statically linked binaries.
*   **Security Restrictions**: For security reasons, the dynamic linker will ignore `LD_PRELOAD` for any binary that has the `setuid` or `setgid` bits set, to prevent privilege escalation attacks.
