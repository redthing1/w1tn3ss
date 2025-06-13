#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <algorithm>
#include <chrono>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#define getpid _getpid
#else
#include <unistd.h>
#endif

class ValidationEngine
{
private:
    static constexpr uint32_t MAGIC_CONSTANT = 0xDEADBEEF;
    static constexpr const char *SECRET_KEY = "w1tn3ss_cr4ckm3";

    bool anti_debug_check()
    {
        // simple timing-based anti-debug (cross-platform)
        auto start = std::chrono::high_resolution_clock::now();
        volatile int dummy = 0;
        for (int i = 0; i < 1000; i++)
        {
            dummy += i;
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        // if execution takes too long, might be debugged
        // more lenient timing for cross-platform compatibility
        return duration.count() < 10000;
    }

    uint32_t hash_string(const std::string &input)
    {
        uint32_t hash = 5381;
        for (char c : input)
        {
            hash = ((hash << 5) + hash) + static_cast<uint32_t>(c);
        }
        return hash ^ MAGIC_CONSTANT;
    }

    bool validate_length(const std::string &input)
    {
        return input.length() >= 8 && input.length() <= 32;
    }

    bool validate_charset(const std::string &input)
    {
        bool has_upper = false, has_lower = false, has_digit = false;

        for (char c : input)
        {
            if (c >= 'A' && c <= 'Z')
                has_upper = true;
            else if (c >= 'a' && c <= 'z')
                has_lower = true;
            else if (c >= '0' && c <= '9')
                has_digit = true;
            else if (c == '_' || c == '-')
                continue;
            else
                return false;
        }

        return has_upper && has_lower && has_digit;
    }

    bool validate_pattern(const std::string &input)
    {
        // must contain "w1" somewhere
        if (input.find("w1") == std::string::npos)
        {
            return false;
        }

        // must not start with digit
        if (!input.empty() && input[0] >= '0' && input[0] <= '9')
        {
            return false;
        }

        // must contain at least 2 uppercase letters
        int upper_count = 0;
        for (char c : input)
        {
            if (c >= 'A' && c <= 'Z')
            {
                upper_count++;
            }
        }

        return upper_count >= 2;
    }

    bool validate_checksum(const std::string &input)
    {
        // the correct password is "w1tn3ss_H4ckM3" but good luck finding it without reversing
        uint32_t expected_hash = 0x1a7a9dde;
        uint32_t actual_hash = hash_string(input);

        // obfuscate the comparison
        uint32_t diff = expected_hash ^ actual_hash;
        return diff == 0;
    }

public:
    enum ValidationResult
    {
        SUCCESS = 0,
        ANTI_DEBUG_FAILED = 1,
        LENGTH_FAILED = 2,
        CHARSET_FAILED = 3,
        PATTERN_FAILED = 4,
        CHECKSUM_FAILED = 5
    };

    ValidationResult validate_input(const std::string &input)
    {
        // stage 1: anti-debug check
        if (!anti_debug_check())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            return ANTI_DEBUG_FAILED;
        }

        // stage 2: length validation
        if (!validate_length(input))
        {
            return LENGTH_FAILED;
        }

        // stage 3: charset validation
        if (!validate_charset(input))
        {
            return CHARSET_FAILED;
        }

        // stage 4: pattern validation
        if (!validate_pattern(input))
        {
            return PATTERN_FAILED;
        }

        // stage 5: final checksum
        if (!validate_checksum(input))
        {
            return CHECKSUM_FAILED;
        }

        return SUCCESS;
    }

    void print_hint(ValidationResult result)
    {
        switch (result)
        {
        case ANTI_DEBUG_FAILED:
            std::cout << "hint: something's watching..." << std::endl;
            break;
        case LENGTH_FAILED:
            std::cout << "hint: length matters (8-32 chars)" << std::endl;
            break;
        case CHARSET_FAILED:
            std::cout << "hint: mix it up (upper, lower, digits, _/-)" << std::endl;
            break;
        case PATTERN_FAILED:
            std::cout << "hint: witness the pattern (w1 + 2 uppercase)" << std::endl;
            break;
        case CHECKSUM_FAILED:
            std::cout << "hint: close, but not quite..." << std::endl;
            break;
        case SUCCESS:
            break;
        }
    }
};

void print_banner()
{
    std::cout << "╔══════════════════════════════════════════════╗" << std::endl;
    std::cout << "║           w1tn3ss control flow #1            ║" << std::endl;
    std::cout << "║              crackme challenge               ║" << std::endl;
    std::cout << "╚══════════════════════════════════════════════╝" << std::endl;
    std::cout << std::endl;
}

void success_message()
{
    std::cout << std::endl;
    std::cout << "*** congratulations! you've cracked it! ***" << std::endl;
    std::cout << "the control flow analysis revealed the path..." << std::endl;
    std::cout << std::endl;
    std::cout << "flag: w1tn3ss{c0ntr0l_fl0w_m4st3r}" << std::endl;
}

void failure_message(int attempts)
{
    std::cout << std::endl;
    if (attempts >= 5)
    {
        std::cout << "*** too many failed attempts. access denied. ***" << std::endl;
        std::cout << "hint: try analyzing the control flow..." << std::endl;
    }
    else
    {
        std::cout << "*** access denied. attempts remaining: " << (5 - attempts) << " ***" << std::endl;
    }
}

int main(int argc, char *argv[])
{
    print_banner();

    ValidationEngine engine;
    std::string input;
    int attempts = 0;
    const int max_attempts = 5;

    // check for command line argument
    if (argc > 1)
    {
        input = argv[1];
        std::cout << "validating provided key: " << input << std::endl;

        auto result = engine.validate_input(input);
        if (result == ValidationEngine::SUCCESS)
        {
            success_message();
            return 0;
        }
        else
        {
            engine.print_hint(result);
            failure_message(1);
            return 1;
        }
    }

    // interactive mode
    std::cout << "enter the access key: ";
    while (attempts < max_attempts && std::getline(std::cin, input))
    {
        attempts++;

        if (input.empty())
        {
            std::cout << "empty input. try again: ";
            continue;
        }

        auto result = engine.validate_input(input);

        if (result == ValidationEngine::SUCCESS)
        {
            success_message();
            return 0;
        }

        engine.print_hint(result);
        failure_message(attempts);

        if (attempts < max_attempts)
        {
            std::cout << "enter the access key: ";
        }
    }

    return 1;
}