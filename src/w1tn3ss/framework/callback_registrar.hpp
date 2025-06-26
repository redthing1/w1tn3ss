/**
 * @file callback_registrar.hpp
 * @brief VM-agnostic QBDI callback registration with SFINAE detection
 * 
 * This component provides template-based callback registration that uses SFINAE
 * to detect which callbacks a tracer implements and only registers those,
 * ensuring zero runtime overhead for unused features.
 * 
 * Works with any QBDI VM instance (owned or external).
 */

#pragma once

#include <redlog/redlog.hpp>
#include <type_traits>
#include <QBDI.h>

namespace w1::framework {

/**
 * @brief VM-agnostic callback registration with SFINAE detection
 * 
 * This class automatically detects which callbacks a tracer implements
 * using SFINAE and registers only the necessary callbacks with any QBDI VM.
 * 
 * @tparam TracerImpl The tracer implementation type
 */
template<typename TracerImpl>
class callback_registrar {
public:
    explicit callback_registrar(const std::string& name = "tracer")
        : log_(redlog::get_logger("w1tn3ss.callback_registrar"))
        , tracer_name_(name) {
        log_.debug("callback registrar created", redlog::field("tracer", tracer_name_));
    }

    /**
     * @brief Register callbacks with the provided QBDI VM
     * 
     * Uses SFINAE to detect which callback methods the tracer implements
     * and only registers those callbacks.
     * 
     * @param vm QBDI VM instance (can be owned or external)
     * @param tracer Tracer instance
     * @return true if registration successful
     */
    bool register_callbacks(QBDI::VM* vm, TracerImpl* tracer) {
        if (!vm || !tracer) {
            log_.error("cannot register callbacks - vm or tracer is null");
            return false;
        }

        vm_ = vm;
        tracer_ = tracer;
        
        log_.debug("registering callbacks", redlog::field("tracer", tracer_name_));

        bool any_registered = false;

        // Register basic block callback if tracer implements it
        if constexpr (has_basic_block_callback_v<TracerImpl>) {
            log_.debug("registering basic block callback");
            uint32_t bb_id = vm_->addVMEventCB(
                QBDI::VMEvent::BASIC_BLOCK_ENTRY,
                reinterpret_cast<QBDI::VMCallback>(basic_block_wrapper),
                this
            );
            
            if (bb_id != QBDI::INVALID_EVENTID) {
                log_.info("basic block callback registered", 
                         redlog::field("callback_id", bb_id),
                         redlog::field("tracer", tracer_name_));
                any_registered = true;
            } else {
                log_.error("failed to register basic block callback");
            }
        } else {
            log_.debug("tracer does not implement basic block callback - skipping");
        }

        // Register instruction callback if tracer implements it
        if constexpr (has_instruction_callback_v<TracerImpl>) {
            log_.debug("registering instruction callback");
            uint32_t inst_id = vm_->addCodeCB(
                QBDI::InstPosition::PREINST,
                reinterpret_cast<QBDI::InstCallback>(instruction_wrapper),
                this
            );
            
            if (inst_id != QBDI::INVALID_EVENTID) {
                log_.info("instruction callback registered", 
                         redlog::field("callback_id", inst_id),
                         redlog::field("tracer", tracer_name_));
                any_registered = true;
            } else {
                log_.error("failed to register instruction callback");
            }
        } else {
            log_.debug("tracer does not implement instruction callback - skipping");
        }

        // Register memory access callback if tracer implements it
        if constexpr (has_memory_callback_v<TracerImpl>) {
            log_.debug("registering memory access callback");
            uint32_t mem_id = vm_->addMemAccessCB(
                QBDI::MemoryAccessType::MEMORY_READ_WRITE,
                reinterpret_cast<QBDI::InstCallback>(memory_wrapper),
                this
            );
            
            if (mem_id != QBDI::INVALID_EVENTID) {
                log_.info("memory access callback registered", 
                         redlog::field("callback_id", mem_id),
                         redlog::field("tracer", tracer_name_));
                any_registered = true;
            } else {
                log_.error("failed to register memory access callback");
            }
        } else {
            log_.debug("tracer does not implement memory callback - skipping");
        }

        if (any_registered) {
            log_.info("callback registration completed", redlog::field("tracer", tracer_name_));
        } else {
            log_.warn("no callbacks were registered", redlog::field("tracer", tracer_name_));
        }

        return any_registered;
    }

    /**
     * @brief Check if callbacks are registered
     */
    bool is_registered() const { return vm_ != nullptr && tracer_ != nullptr; }

private:
    redlog::logger log_;
    std::string tracer_name_;
    QBDI::VM* vm_ = nullptr;
    TracerImpl* tracer_ = nullptr;

    // SFINAE detection for callback methods (C++17 compatible)
    template<typename T, typename = void>
    struct has_basic_block_callback : std::false_type {};
    
    template<typename T>
    struct has_basic_block_callback<T, std::void_t<decltype(std::declval<T>().on_basic_block(
        std::declval<uint64_t>(), std::declval<uint16_t>()))>> : std::true_type {};
    
    template<typename T, typename = void>
    struct has_instruction_callback : std::false_type {};
    
    template<typename T>
    struct has_instruction_callback<T, std::void_t<decltype(std::declval<T>().on_instruction(
        std::declval<uint64_t>()))>> : std::true_type {};
    
    template<typename T, typename = void>
    struct has_memory_callback : std::false_type {};
    
    template<typename T>
    struct has_memory_callback<T, std::void_t<decltype(std::declval<T>().on_memory_access(
        std::declval<uint64_t>(), std::declval<size_t>(), std::declval<bool>()))>> : std::true_type {};

    template<typename T>
    static constexpr bool has_basic_block_callback_v = has_basic_block_callback<T>::value;
    
    template<typename T>
    static constexpr bool has_instruction_callback_v = has_instruction_callback<T>::value;
    
    template<typename T>
    static constexpr bool has_memory_callback_v = has_memory_callback<T>::value;

    // Callback wrappers
    static QBDI::VMAction basic_block_wrapper(
        QBDI::VMInstanceRef vm, const QBDI::VMState* vmState, 
        QBDI::GPRState* gprState, QBDI::FPRState* fprState, void* data) {
        
        
        auto* registrar = static_cast<callback_registrar*>(data);
        if (!registrar || !registrar->tracer_ || !vmState) {
            return QBDI::VMAction::CONTINUE;
        }

        try {
            uint64_t bb_start = vmState->basicBlockStart;
            uint16_t bb_size = static_cast<uint16_t>(vmState->basicBlockEnd - vmState->basicBlockStart);
            
            if constexpr (has_basic_block_callback_v<TracerImpl>) {
                registrar->tracer_->on_basic_block(bb_start, bb_size);
            }
        } catch (const std::exception& e) {
            registrar->log_.error("error in basic block callback", 
                                 redlog::field("error", e.what()),
                                 redlog::field("tracer", registrar->tracer_name_));
        }

        return QBDI::VMAction::CONTINUE;
    }

    static QBDI::VMAction instruction_wrapper(
        QBDI::VMInstanceRef vm, QBDI::GPRState* gprState, 
        QBDI::FPRState* fprState, void* data) {
        
        auto* registrar = static_cast<callback_registrar*>(data);
        if (!registrar || !registrar->tracer_ || !vm) {
            return QBDI::VMAction::CONTINUE;
        }

        try {
            QBDI::VM* qbdi_vm = static_cast<QBDI::VM*>(vm);
            const QBDI::InstAnalysis* analysis = qbdi_vm->getInstAnalysis();
            
            if (analysis && analysis->address) {
                if constexpr (has_instruction_callback_v<TracerImpl>) {
                    registrar->tracer_->on_instruction(analysis->address);
                }
            }
        } catch (const std::exception& e) {
            registrar->log_.error("error in instruction callback", 
                                 redlog::field("error", e.what()),
                                 redlog::field("tracer", registrar->tracer_name_));
        }

        return QBDI::VMAction::CONTINUE;
    }

    static QBDI::VMAction memory_wrapper(
        QBDI::VMInstanceRef vm, QBDI::GPRState* gprState, 
        QBDI::FPRState* fprState, void* data) {
        
        auto* registrar = static_cast<callback_registrar*>(data);
        if (!registrar || !registrar->tracer_ || !vm) {
            return QBDI::VMAction::CONTINUE;
        }

        try {
            QBDI::VM* qbdi_vm = static_cast<QBDI::VM*>(vm);
            std::vector<QBDI::MemoryAccess> accesses = qbdi_vm->getInstMemoryAccess();
            
            for (const auto& access : accesses) {
                if constexpr (has_memory_callback_v<TracerImpl>) {
                    bool is_write = (access.type & QBDI::MemoryAccessType::MEMORY_WRITE) != 0;
                    registrar->tracer_->on_memory_access(access.accessAddress, access.size, is_write);
                }
            }
        } catch (const std::exception& e) {
            registrar->log_.error("error in memory callback", 
                                 redlog::field("error", e.what()),
                                 redlog::field("tracer", registrar->tracer_name_));
        }

        return QBDI::VMAction::CONTINUE;
    }
};

} // namespace w1::framework