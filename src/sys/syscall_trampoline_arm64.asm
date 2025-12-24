; (c) Alexander 'xaitax' Hagenah
; Licensed under the MIT License. See LICENSE file in the project root for full license information.
;
; A simple and ABI-compliant ARM64 trampoline. This version preserves callee-saved
; registers and uses a direct marshalling approach that is proven to work for
; this project's specific set of required syscalls.

    AREA    |.text|, CODE, READONLY, ALIGN=4
    EXPORT  SyscallTrampoline

SyscallTrampoline PROC
    ; — Prologue: Preserve callee-saved registers —
    ; The ARM64 ABI requires that we save any callee-saved registers we use.
    ; We use x19 for the SYSCALL_ENTRY* and x30 (the link register) is implicitly used.
    stp     x19, x30, [sp, #-16]!

    ; — Preserve SYSCALL_ENTRY* pointer —
    ; We save it in a preserved register (x19) for use throughout the function.
    mov     x19, x0

    ; — Allocate stack space for potential syscall stack arguments —
    ; This unconditionally allocates space for up to 3 stack arguments (e.g., for
    ; NtCreateThreadEx) and ensures the stack remains 16-byte aligned. For functions
    ; with fewer arguments, this space is unused but harmless.
    sub     sp, sp, #32

    ; — Unconditionally marshal C-level stack arguments —
    ; The C caller's stack is now at sp + 32(our alloc) + 16(our saved regs).
    ldr     x10, [sp, #32+16+8]     ; Load C-Arg 9 (StackSize)
    str     x10, [sp, #0]           ; Store as Syscall-Arg 9 on our local stack
    ldr     x10, [sp, #32+16+16]    ; Load C-Arg 10 (MaximumStackSize)
    str     x10, [sp, #8]           ; Store as Syscall-Arg 10
    ldr     x10, [sp, #32+16+24]    ; Load C-Arg 11 (AttributeList)
    str     x10, [sp, #16]          ; Store as Syscall-Arg 11

    ; — Marshal C arguments to the ARM64 Syscall Convention —
    ; Syscall convention requires arguments in: x0-x7.
    mov     x0, x1                  ; C-Arg2  -> Syscall-Arg1 (x0)
    mov     x1, x2                  ; C-Arg3  -> Syscall-Arg2 (x1)
    mov     x2, x3                  ; C-Arg4  -> Syscall-Arg3 (x2)
    mov     x3, x4                  ; C-Arg5  -> Syscall-Arg4 (x3)
    mov     x4, x5                  ; C-Arg6  -> Syscall-Arg5 (x4)
    mov     x5, x6                  ; C-Arg7  -> Syscall-Arg6 (x5)
    mov     x6, x7                  ; C-Arg8  -> Syscall-Arg7 (x6)
    ldr     x7, [sp, #32+16]        ; C-Arg9 (from caller's stack) -> Syscall-Arg8 (x7)

    ; — Final preparation for kernel transition —
    ; Load the Syscall Service Number (SSN) into x8.
    ; CRITICAL FIX: The SSN is now at offset 12 in the SYSCALL_ENTRY struct.
    ldrh    w8, [x19, #12]

    ; Load the gadget pointer for dispatch.
    ldr     x10, [x19, #0]          ; Load pSyscallGadget from SYSCALL_ENTRY (offset 0).

    ; — Dispatch the syscall —
    ; Branch with Link to Register. Gadget must contain `svc #imm; ret`.
    blr     x10

    ; — Epilogue: Cleanly unwind and return to C++ —
    ; The NTSTATUS result is already in x0, the correct return register.
    add     sp, sp, #32             ; Deallocate our local stack space.
    ldp     x19, x30, [sp], #16     ; Restore preserved registers from the stack.
    ret                             ; Return to the C++ caller.

    ENDP
    END
