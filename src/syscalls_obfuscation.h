// syscalls_obfuscation.h
// v0.16.1 (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#ifndef SYSCALLS_OBFUSCATION_H
#define SYSCALLS_OBFUSCATION_H

#include <Windows.h>
#include <cstdint>
#include <intrin.h>
#include "syscalls.h"

namespace SyscallObfuscation
{
    // XOR encryption keys (randomized at runtime)
    struct ObfuscationKeys
    {
        uint64_t ssnKey;    // Key for SSN encryption
        uint64_t gadgetKey; // Key for gadget pointer encryption
        uint64_t structKey; // Key for structure field shuffling
        bool initialized;
    };

    // Encrypted syscall entry
    struct ObfuscatedSyscallEntry
    {
        uint64_t encryptedGadget; // XOR'd gadget pointer
        uint32_t encryptedSSN;    // XOR'd SSN
        uint32_t checksum;        // Integrity check
        uint8_t padding[16];      // Anti-pattern padding
    };

    // Anti-debugging/analysis checks
    namespace AntiAnalysis
    {
        // Check for debugger presence via PEB
        inline bool IsDebuggerPresent_PEB()
        {
#if defined(_M_X64)
            PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#elif defined(_M_ARM64)
            PPEB peb = reinterpret_cast<PPEB>(__readx18qword(0x60));
#else
            return false;
#endif
            return peb && peb->BeingDebugged;
        }

        // Timing-based debugger detection
        inline bool IsDebuggerPresent_Timing()
        {
#if defined(_M_X64) || defined(_M_IX86)
            uint64_t start = __rdtsc();

            // Junk operations to create timing window
            volatile int x = 0;
            for (int i = 0; i < 10; i++)
                x += i;

            uint64_t end = __rdtsc();

            // If took too long, likely stepped through debugger
            return (end - start) > 10000;
#else
            // ARM64: Use GetTickCount64 as fallback
            ULONGLONG start = GetTickCount64();
            volatile int x = 0;
            for (int i = 0; i < 10; i++)
                x += i;
            ULONGLONG end = GetTickCount64();
            return (end - start) > 50;
#endif
        }

        // Check for hardware breakpoints via debug registers
        inline bool HasHardwareBreakpoints()
        {
#if defined(_M_X64) || defined(_M_IX86)
            CONTEXT ctx = {};
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

            if (!GetThreadContext(GetCurrentThread(), &ctx))
                return false;

            // Check if any debug registers are set
            return (ctx.Dr0 | ctx.Dr1 | ctx.Dr2 | ctx.Dr3) != 0;
#else
            // ARM64 doesn't have the same debug register structure in CONTEXT
            // Use alternative detection method
            return false;
#endif
        }

        // Anti-analysis check
        inline bool DetectAnalysisEnvironment()
        {
            // Multiple detection vectors
            if (IsDebuggerPresent_PEB())
                return true;
            if (IsDebuggerPresent_Timing())
                return true;
            if (HasHardwareBreakpoints())
                return true;
            if (IsDebuggerPresent())
                return true; // Win32 API fallback

            return false;
        }
    }

    // Obfuscation utilities
    namespace Utils
    {
        // Generate pseudo-random key based on runtime state
        inline uint64_t GenerateRuntimeKey()
        {
#if defined(_M_X64) || defined(_M_IX86)
            uint64_t key = __rdtsc();
#else
            // ARM64: Use performance counter
            LARGE_INTEGER counter;
            QueryPerformanceCounter(&counter);
            uint64_t key = static_cast<uint64_t>(counter.QuadPart);
#endif
            key ^= reinterpret_cast<uint64_t>(&key);
            key ^= static_cast<uint64_t>(GetCurrentProcessId()) << 32;
            key ^= static_cast<uint64_t>(GetCurrentThreadId());

            // Mix bits
            key ^= (key << 13);
            key ^= (key >> 7);
            key ^= (key << 17);

            return key;
        }

        // XOR encrypt pointer
        inline uint64_t EncryptPointer(PVOID ptr, uint64_t key)
        {
            return reinterpret_cast<uint64_t>(ptr) ^ key;
        }

        // XOR decrypt pointer
        inline PVOID DecryptPointer(uint64_t encrypted, uint64_t key)
        {
            return reinterpret_cast<PVOID>(encrypted ^ key);
        }

        // XOR encrypt SSN
        inline uint32_t EncryptSSN(WORD ssn, uint64_t key)
        {
            return static_cast<uint32_t>(ssn) ^ static_cast<uint32_t>(key & 0xFFFFFFFF);
        }

        // XOR decrypt SSN
        inline WORD DecryptSSN(uint32_t encrypted, uint64_t key)
        {
            return static_cast<WORD>(encrypted ^ static_cast<uint32_t>(key & 0xFFFFFFFF));
        }

        // Calculate simple checksum for integrity
        inline uint32_t CalculateChecksum(uint64_t gadget, uint32_t ssn)
        {
            uint32_t sum = static_cast<uint32_t>(gadget & 0xFFFFFFFF);
            sum ^= static_cast<uint32_t>(gadget >> 32);
            sum ^= ssn;
            sum = (sum << 13) | (sum >> 19); // Rotate
            return sum;
        }

        // Junk code injection to break pattern analysis
        inline void InjectJunkCode()
        {
#if defined(_M_X64) || defined(_M_IX86)
            volatile uint64_t junk = __rdtsc();
#else
            LARGE_INTEGER counter;
            QueryPerformanceCounter(&counter);
            volatile uint64_t junk = static_cast<uint64_t>(counter.QuadPart);
#endif
            junk = (junk * 0x41C64E6D + 0x3039) & 0xFFFFFFFF;
            junk ^= (junk << 21);
            junk ^= (junk >> 35);
            junk ^= (junk << 4);
            // Compiler won't optimize this away due to volatile
        }
    }

    // Main obfuscation manager
    class SyscallObfuscator
    {
    private:
        ObfuscationKeys m_keys;
        bool m_antiAnalysisEnabled;

        // Initialize encryption keys
        void InitializeKeys()
        {
            m_keys.ssnKey = Utils::GenerateRuntimeKey();
            m_keys.gadgetKey = Utils::GenerateRuntimeKey() ^ 0xDEADBEEFCAFEBABE;
            m_keys.structKey = Utils::GenerateRuntimeKey() ^ 0x1337C0DEC0FFEE;
            m_keys.initialized = true;
        }

    public:
        SyscallObfuscator(bool enableAntiAnalysis = true)
            : m_antiAnalysisEnabled(enableAntiAnalysis)
        {
            m_keys = {};
            InitializeKeys();
        }

        // Check for analysis environment before critical operations
        bool ValidateEnvironment()
        {
            if (!m_antiAnalysisEnabled)
                return true;

            Utils::InjectJunkCode();

            if (AntiAnalysis::DetectAnalysisEnvironment())
                return false;

            Utils::InjectJunkCode();
            return true;
        }

        // Encrypt syscall entry
        ObfuscatedSyscallEntry EncryptEntry(PVOID gadget, WORD ssn)
        {
            Utils::InjectJunkCode();

            ObfuscatedSyscallEntry entry = {};
            entry.encryptedGadget = Utils::EncryptPointer(gadget, m_keys.gadgetKey);
            entry.encryptedSSN = Utils::EncryptSSN(ssn, m_keys.ssnKey);
            entry.checksum = Utils::CalculateChecksum(
                reinterpret_cast<uint64_t>(gadget),
                static_cast<uint32_t>(ssn));

            // Fill padding with pseudo-random data to break patterns
            for (int i = 0; i < 16; i++)
                entry.padding[i] = static_cast<uint8_t>((m_keys.structKey >> (i * 4)) & 0xFF);

            Utils::InjectJunkCode();
            return entry;
        }

        // Decrypt and validate syscall entry
        bool DecryptEntry(const ObfuscatedSyscallEntry &entry, PVOID *outGadget, WORD *outSSN)
        {
            Utils::InjectJunkCode();

            PVOID gadget = Utils::DecryptPointer(entry.encryptedGadget, m_keys.gadgetKey);
            WORD ssn = Utils::DecryptSSN(entry.encryptedSSN, m_keys.ssnKey);

            // Verify integrity
            uint32_t calculatedChecksum = Utils::CalculateChecksum(
                reinterpret_cast<uint64_t>(gadget),
                static_cast<uint32_t>(ssn));

            if (calculatedChecksum != entry.checksum)
                return false; // Tampered data

            *outGadget = gadget;
            *outSSN = ssn;

            Utils::InjectJunkCode();
            return true;
        }

        // Re-randomize keys
        void RotateKeys()
        {
            Utils::InjectJunkCode();

            // XOR with new random values instead of complete replacement
            m_keys.ssnKey ^= Utils::GenerateRuntimeKey();
            m_keys.gadgetKey ^= Utils::GenerateRuntimeKey();
            m_keys.structKey ^= Utils::GenerateRuntimeKey();

            Utils::InjectJunkCode();
        }

        // Get keys for external encryption (use sparingly)
        const ObfuscationKeys &GetKeys() const { return m_keys; }
    };

    // Global obfuscator instance (initialized once)
    extern SyscallObfuscator *g_Obfuscator;

    // Initialize obfuscation system
    inline bool InitializeObfuscation(bool enableAntiAnalysis = true)
    {
        if (g_Obfuscator)
            return true; // Already initialized

        g_Obfuscator = new SyscallObfuscator(enableAntiAnalysis);
        return g_Obfuscator != nullptr;
    }

    // Cleanup obfuscation system
    inline void CleanupObfuscation()
    {
        if (g_Obfuscator)
        {
            delete g_Obfuscator;
            g_Obfuscator = nullptr;
        }
    }
}

#endif
