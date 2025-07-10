; syscall_trampoline_x64.asm
; v0.13.0 (c) Alexander 'xaitax' Hagenah
; Licensed under the MIT License. See LICENSE file in the project root for full license information.
;
; The definitive, ABI-compliant, and argument-aware x64 trampoline.
; This version combines a stable stack frame with meticulous preservation of
; non-volatile registers, guaranteeing no corruption of the C++ caller's state.

.code
ALIGN 16
PUBLIC SyscallTrampoline

SyscallTrampoline PROC FRAME
    ; — Prologue: Establish a stable, ABI-compliant stack frame —
    ; We push RBP to create the frame, then immediately push every non-volatile
    ; register that this function will modify. This is the most critical step
    ; for preventing caller-state corruption.
    push    rbp
    mov     rbp, rsp
    push    r12
    push    r13
    push    rdi
    push    rsi
    sub     rsp, 64         ; Allocate stack space for shadow space and locals.

    ; Mark the end of the prologue for the ml64 assembler.
    .ENDPROLOG

    ; — Preserve SYSCALL_ENTRY* pointer —
    ; We save it in a preserved register (R12) for use throughout the function.
    mov     r12, rcx

    ; — Marshal C arguments to the x64 Syscall Convention —
    ; Kernel requires arguments in: R10, RDX, R8, R9, and then the stack.
    mov     rcx, rdx        ; C-Arg2 (e.g., ProcessHandle) -> goes into RCX temporarily.
    mov     rdx, r8         ; C-Arg3 -> Syscall-Arg2 (RDX)
    mov     r8,  r9         ; C-Arg4 -> Syscall-Arg3 (R8)
    mov     r9,  [rbp+30h]   ; C-Arg5 (from original caller's stack) -> Syscall-Arg4 (R9)

    ; — Dynamically marshal stack arguments using an argument-aware loop —
    ; This prevents reading garbage from the caller's stack, which would cause
    ; STATUS_INVALID_PARAMETER_MIX errors.
    mov     r13d, [r12+8]   ; Load nArgs from SYSCALL_ENTRY into our preserved R13 register.
    cmp     r13d, 4
    jle     _DispatchSetup  ; If 4 or fewer args, no stack marshalling is needed.
    
    sub     r13d, 4         ; R13d now holds the exact count of stack args to move.
    
    ; Prepare pointers for the block move using our preserved registers.
    lea     rdi, [rsp+20h]  ; RDI = Destination (Syscall-Arg 5's slot on our local stack).
    lea     rsi, [rbp+38h]  ; RSI = Source (C-Arg 6's slot on the caller's stack).
    
    push    rcx             ; Temporarily save Syscall-Arg1, as REP MOVSQ uses RCX.
    mov     ecx, r13d       ; Load the argument count into the loop counter.
    rep     movsq           ; Execute the block move of QWORDs.
    pop     rcx             ; Restore Syscall-Arg1.

_DispatchSetup:
    ; — Final preparation for kernel transition —
    ; Emulate the mandatory ntdll stub behavior to prevent STATUS_INVALID_HANDLE.
    mov     r10, rcx        ; Copy Syscall-Arg1 from RCX to R10.

    ; Load the SSN and gadget address.
    movzx   eax, word ptr [r12+12] ; Load ssn from SYSCALL_ENTRY (offset 12).
    mov     r11, [r12]             ; Load pSyscallGadget from SYSCALL_ENTRY (offset 0).

    ; — Dispatch the syscall —
    call    r11

    ; — Epilogue: Cleanly unwind and return to C++ —
    ; The NTSTATUS result is already in RAX, the correct return register.
    add     rsp, 64         ; Deallocate local stack space.
    pop     rsi             ; Restore all preserved registers in reverse order.
    pop     rdi
    pop     r13
    pop     r12
    pop     rbp             ; Restore the caller's frame pointer.
    ret
SyscallTrampoline ENDP
END
