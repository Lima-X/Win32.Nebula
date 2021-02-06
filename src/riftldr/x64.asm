; Thread-Interrupt-Dispatcher - START ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Offsets
CONTEXT_RAX    equ 78h ; offset of Rax in CONTEXT

CALLBACK       equ 10h ; Shadowspace (used for parameter passing)
USER_CONTEXT   equ 18h
THREAD_CONTEXT equ 20h
RTL_BARRIER    equ 28h

;; Required Win32 Api's
includelib ntdllp.lib
includelib kernel32.lib
extern NtContinueEx                : proc
extern EnterSynchronizationBarrier : proc
extern RaiseException              : proc
.code

;; Thread Interrupt Dispatcher - Similar to ntdll!KiUserApcDispatcher
ThreadInterruptDispatcher proc FRAME
.endprolog
	;; Store returnvalue (syscall handling)
	lea  rbx, [rsp + THREAD_CONTEXT] ; Load address of restorepoint
	mov  [rbx + CONTEXT_RAX], rax    ; Safe retunvalue

	;; Call userdefined Callback
	mov  rcx, [rsp + USER_CONTEXT]   ; Load UserText
	mov  rax, [rsp + CALLBACK]       ; Load Callback
	call rax                         ; Call Callback

	;; Synchronize apc's (optional)
	mov  rcx, [rsp + RTL_BARRIER]    ; Load barrier address
	test rcx, rcx                    ; Check if ptr is valid
	jz   RestoreContext              ; If not nullptr coninue
	xor  rdx, rdx                    ; null second parameter
	call EnterSynchronizationBarrier ; Call Synchronization

RestoreContext:
	;; Restore original thread context
	mov  rcx, [rsp + THREAD_CONTEXT] ; Load restorepoint
	xor  rdx, rdx                    ; null second parameter
	call NtContinueEx                ; Call NtContinueEx
	mov [rsp], rax                   ; Store error code

	; First try to raise an exception (let the programm handle the issue)
	mov rcx, rax                     ; Pass error code
	xor rdx, rdx                     ; Zero second to last parameter
	mov r8,  rdx
	mov r9,  rdx
	call RaiseException              ; Call RaiseException

	; Incase the exception was handled but code execution still continues
	; terminate the programm forcefully / quickly
	mov ecx, [rsp]                   ; ErrorCode
	int 29h                          ; __fastfail
ThreadInterruptDispatcher endp
; Thread-Interrupt-Dispatcher - END ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
end