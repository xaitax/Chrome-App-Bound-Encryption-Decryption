; (c) Alexander 'xaitax' Hagenah
; Licensed under the MIT License. See LICENSE file in the project root for full license information.
;
; ABI-compliant x64 trampoline with unconditional marshalling for max arguments.
; Allocates sufficient stack to prevent overwrite issues. Uses rep movsq for efficient block copy.
; Preserves necessary non-volatile registers. Eliminates dynamic loop to reduce complexity and potential errors.
; Sets SSN before dispatching to gadget. Handles up to 11 syscall arguments safely (copies 8 stack slots, extra as harmless garbage).

.code
ALIGN 16
PUBLIC SyscallTrampoline

SyscallTrampoline PROC FRAME
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    rdi
    push    rsi
    sub     rsp, 80h              ; Allocate 128 bytes: safe for shadow (0x20) + 8 qwords (0x40) + padding
    .ENDPROLOG

    mov     rbx, rcx              ; Preserve SYSCALL_ENTRY* in rbx (non-volatile)

    ; Marshal register-based arguments (shifted due to extra SYSCALL_ENTRY* parameter)
    mov     r10, rdx              ; Syscall-Arg1 <- C-Arg2
    mov     rdx, r8               ; Syscall-Arg2 <- C-Arg3
    mov     r8, r9                ; Syscall-Arg3 <- C-Arg4
    mov     r9, [rbp+30h]         ; Syscall-Arg4 <- C-Arg5 (from caller's stack)

    ; Unconditionally marshal 8 stack arguments (covers max of 7 needed + 1 extra; garbage for fewer is harmless)
    lea     rsi, [rbp+38h]        ; Source: C-Arg6 (Syscall-Arg5 position in caller's stack)
    lea     rdi, [rsp+20h]        ; Destination: Syscall-Arg5 position in local stack
    mov     rcx, 8                ; Copy 8 qwords (64 bytes)
    rep     movsq                 ; Block copy (efficient and modular)

    ; Prepare for kernel transition
    movzx   eax, word ptr [rbx+12] ; Load SSN into EAX
    mov     r11, [rbx]             ; Load gadget address

    call    r11                    ; Dispatch to gadget (syscall; ret)

    ; Epilogue: Restore stack and registers
    add     rsp, 80h
    pop     rsi
    pop     rdi
    pop     rbx
    pop     rbp
    ret
SyscallTrampoline ENDP
END
