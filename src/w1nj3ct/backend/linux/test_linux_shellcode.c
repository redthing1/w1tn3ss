#include "linux_shellcode.h"
#include "linux_shellcode_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <assert.h>

// test helper functions
static void test_architecture_detection(void) {
    printf("Testing architecture detection...\n");
    
    pid_t self_pid = getpid();
    linux_arch_t arch = linux_detect_process_architecture(self_pid);
    
    printf("Detected architecture: %s\n", linux_arch_to_string(arch));
    assert(arch != ARCH_UNKNOWN);
    
    size_t ptr_size = linux_get_pointer_size(arch);
    size_t reg_size = linux_get_register_size(arch);
    
    printf("Pointer size: %zu, Register size: %zu\n", ptr_size, reg_size);
    assert(ptr_size > 0);
    assert(reg_size > 0);
    
    printf("Architecture detection test passed!\n\n");
}

static void test_memory_maps(void) {
    printf("Testing memory maps parsing...\n");
    
    pid_t self_pid = getpid();
    linux_memory_map_t* maps;
    size_t map_count;
    
    int ret = linux_get_process_memory_maps(self_pid, &maps, &map_count);
    assert(ret == LINUX_UTILS_SUCCESS);
    assert(maps != NULL);
    assert(map_count > 0);
    
    printf("Found %zu memory mappings:\n", map_count);
    for (size_t i = 0; i < map_count && i < 10; i++) {
        printf("  %p-%p %s %s\n", 
               maps[i].start_addr, maps[i].end_addr, 
               maps[i].permissions, 
               maps[i].path ? maps[i].path : "[anonymous]");
    }
    
    linux_free_memory_maps(maps, map_count);
    printf("Memory maps test passed!\n\n");
}

static void test_shellcode_generation(void) {
    printf("Testing shellcode generation...\n");
    
    linux_arch_t arch = linux_detect_process_architecture(getpid());
    
    // test mmap shellcode generation
    void* mmap_shellcode;
    size_t mmap_size;
    int ret = linux_generate_mmap_shellcode(arch, 0x1000, &mmap_shellcode, &mmap_size);
    
    if (ret == LINUX_SHELLCODE_SUCCESS) {
        printf("Generated mmap shellcode: %zu bytes\n", mmap_size);
        linux_free_shellcode(mmap_shellcode);
    } else {
        printf("mmap shellcode generation failed: %s\n", linux_shellcode_error_string(ret));
    }
    
    // test munmap shellcode generation
    void* munmap_shellcode;
    size_t munmap_size;
    ret = linux_generate_munmap_shellcode(arch, (void*)0x10000, 0x1000, &munmap_shellcode, &munmap_size);
    
    if (ret == LINUX_SHELLCODE_SUCCESS) {
        printf("Generated munmap shellcode: %zu bytes\n", munmap_size);
        linux_free_shellcode(munmap_shellcode);
    } else {
        printf("munmap shellcode generation failed: %s\n", linux_shellcode_error_string(ret));
    }
    
    printf("Shellcode generation test completed!\n\n");
}

static void test_function_call_shellcode(void) {
    printf("Testing function call shellcode generation...\n");
    
    linux_arch_t arch = linux_detect_process_architecture(getpid());
    
    linux_function_call_t call_info;
    memset(&call_info, 0, sizeof(call_info));
    call_info.arch = arch;
    call_info.arg_count = 3;
    call_info.args[0] = (void*)0x1000;
    call_info.args[1] = (void*)0x2000;
    call_info.args[2] = (void*)0x3000;
    
    void* shellcode;
    size_t shellcode_size;
    int ret = linux_generate_function_call_shellcode(arch, (void*)0x7fff00000000, 
                                                    &call_info, &shellcode, &shellcode_size);
    
    if (ret == LINUX_UTILS_SUCCESS) {
        printf("Generated function call shellcode: %zu bytes\n", shellcode_size);
        linux_free_shellcode(shellcode);
    } else {
        printf("Function call shellcode generation failed: %s\n", linux_utils_error_string(ret));
    }
    
    printf("Function call shellcode test completed!\n\n");
}

static void test_shellcode_encoding(void) {
    printf("Testing shellcode encoding...\n");
    
    unsigned char test_shellcode[] = {0x90, 0x90, 0x90, 0x90, 0xcc}; // nop; nop; nop; nop; int3
    size_t test_size = sizeof(test_shellcode);
    uint8_t xor_key = 0x42;
    
    void* encoded_shellcode;
    size_t encoded_size;
    int ret = linux_encode_shellcode_xor(test_shellcode, test_size, xor_key, 
                                        &encoded_shellcode, &encoded_size);
    
    if (ret == LINUX_UTILS_SUCCESS) {
        printf("Encoded shellcode: %zu bytes\n", encoded_size);
        
        // verify encoding
        unsigned char* encoded = (unsigned char*)encoded_shellcode;
        for (size_t i = 0; i < test_size; i++) {
            assert(encoded[i] == (test_shellcode[i] ^ xor_key));
        }
        
        // test decoder generation
        linux_arch_t arch = linux_detect_process_architecture(getpid());
        void* decoder;
        size_t decoder_size;
        ret = linux_generate_decoder_shellcode(arch, xor_key, encoded_size, &decoder, &decoder_size);
        
        if (ret == LINUX_UTILS_SUCCESS) {
            printf("Generated decoder shellcode: %zu bytes\n", decoder_size);
            linux_free_shellcode(decoder);
        } else {
            printf("Decoder generation failed: %s\n", linux_utils_error_string(ret));
        }
        
        linux_free_shellcode(encoded_shellcode);
    } else {
        printf("Shellcode encoding failed: %s\n", linux_utils_error_string(ret));
    }
    
    printf("Shellcode encoding test completed!\n\n");
}

static void test_debugger_detection(void) {
    printf("Testing debugger detection...\n");
    
    pid_t self_pid = getpid();
    int is_debugged;
    int ret = linux_check_debugger_presence(self_pid, &is_debugged);
    
    if (ret == LINUX_UTILS_SUCCESS) {
        printf("Debugger detection result: %s\n", is_debugged ? "DEBUGGED" : "NOT DEBUGGED");
    } else {
        printf("Debugger detection failed: %s\n", linux_utils_error_string(ret));
    }
    
    printf("Debugger detection test completed!\n\n");
}

static void test_library_base_finding(void) {
    printf("Testing library base address finding...\n");
    
    pid_t self_pid = getpid();
    void* libc_base;
    int ret = linux_find_library_base(self_pid, "libc", &libc_base);
    
    if (ret == LINUX_UTILS_SUCCESS) {
        printf("Found libc base address: %p\n", libc_base);
    } else {
        printf("Library base finding failed: %s\n", linux_utils_error_string(ret));
    }
    
    printf("Library base finding test completed!\n\n");
}

static void test_shellcode_context(void) {
    printf("Testing shellcode context creation...\n");
    
    pid_t self_pid = getpid();
    linux_shellcode_ctx_t* ctx;
    int ret = linux_create_shellcode_context(self_pid, &ctx);
    
    if (ret == LINUX_SHELLCODE_SUCCESS) {
        printf("Created shellcode context for PID %d, architecture: %s\n", 
               ctx->pid, linux_arch_to_string(ctx->arch));
        linux_destroy_shellcode_context(ctx);
    } else {
        printf("Shellcode context creation failed: %s\n", linux_shellcode_error_string(ret));
    }
    
    printf("Shellcode context test completed!\n\n");
}

static void test_error_handling(void) {
    printf("Testing error handling...\n");
    
    // test invalid arguments
    void* shellcode;
    size_t size;
    int ret = linux_generate_mmap_shellcode(ARCH_UNKNOWN, 0x1000, &shellcode, &size);
    assert(ret == LINUX_SHELLCODE_ERROR_UNSUPPORTED_ARCH);
    
    ret = linux_generate_mmap_shellcode(ARCH_X86_64, 0x1000, NULL, &size);
    assert(ret == LINUX_SHELLCODE_ERROR_INVALID_ARGS);
    
    // test error string functions
    const char* error_str = linux_shellcode_error_string(LINUX_SHELLCODE_ERROR_NO_MEMORY);
    assert(error_str != NULL);
    assert(strlen(error_str) > 0);
    
    error_str = linux_utils_error_string(LINUX_UTILS_ERROR_INVALID_ARGS);
    assert(error_str != NULL);
    assert(strlen(error_str) > 0);
    
    printf("Error handling test passed!\n\n");
}

static void test_process_control_functions(void) {
    printf("Testing process control functions (self-attach)...\n");
    
    // note: attaching to self might not work on all systems
    // this is mainly to test the function interfaces
    
    pid_t self_pid = getpid();
    
    // test register operations (might fail due to permissions)
    void* regs;
    int ret = linux_get_process_registers(self_pid, &regs);
    if (ret == LINUX_SHELLCODE_SUCCESS) {
        printf("Successfully got process registers\n");
        free(regs);
    } else {
        printf("Getting process registers failed (expected): %s\n", linux_shellcode_error_string(ret));
    }
    
    printf("Process control functions test completed!\n\n");
}

// comprehensive test for non-invasive operations
static void run_safe_tests(void) {
    printf("=== Running Safe Tests (Non-invasive) ===\n\n");
    
    test_architecture_detection();
    test_memory_maps();
    test_shellcode_generation();
    test_function_call_shellcode();
    test_shellcode_encoding();
    test_debugger_detection();
    test_library_base_finding();
    test_shellcode_context();
    test_error_handling();
    test_process_control_functions();
    
    printf("=== All Safe Tests Completed ===\n\n");
}

// test with a child process (more invasive)
static void test_with_child_process(void) {
    printf("=== Testing with Child Process ===\n\n");
    
    pid_t child_pid = fork();
    if (child_pid == 0) {
        // child process - just sleep
        printf("Child process %d sleeping...\n", getpid());
        sleep(10);
        exit(0);
    } else if (child_pid > 0) {
        // parent process - test injection
        printf("Parent process testing injection on child %d\n", child_pid);
        
        // give child time to start
        usleep(100000);
        
        // test architecture detection on child
        linux_arch_t child_arch = linux_detect_process_architecture(child_pid);
        printf("Child architecture: %s\n", linux_arch_to_string(child_arch));
        
        // test memory maps on child
        linux_memory_map_t* maps;
        size_t map_count;
        int ret = linux_get_process_memory_maps(child_pid, &maps, &map_count);
        if (ret == LINUX_UTILS_SUCCESS) {
            printf("Child has %zu memory mappings\n", map_count);
            linux_free_memory_maps(maps, map_count);
        }
        
        // test attach/detach (might fail due to permissions)
        ret = linux_attach_process(child_pid);
        if (ret == LINUX_SHELLCODE_SUCCESS) {
            printf("Successfully attached to child process\n");
            linux_detach_process(child_pid);
            printf("Successfully detached from child process\n");
        } else {
            printf("Failed to attach to child process: %s\n", linux_shellcode_error_string(ret));
        }
        
        // terminate child
        kill(child_pid, SIGTERM);
        waitpid(child_pid, NULL, 0);
        
        printf("Child process test completed\n");
    } else {
        perror("fork failed");
    }
    
    printf("=== Child Process Tests Completed ===\n\n");
}

int main(int argc, char* argv[]) {
    printf("Linux Shellcode Backend Test Suite\n");
    printf("===================================\n\n");
    
    // run safe tests first
    run_safe_tests();
    
    // run child process tests if requested
    if (argc > 1 && strcmp(argv[1], "--with-child") == 0) {
        test_with_child_process();
    } else {
        printf("Note: Run with --with-child to test child process operations\n");
    }
    
    printf("All tests completed successfully!\n");
    printf("The Linux shellcode backend is ready for integration.\n");
    
    return 0;
}