// No Runtime Library : Provides subroutines for the compiler that emulate the CRT
#pragma once
#include "sub/sub.h"

// Inline Definitions / Macros
#define memset(_Dst, _Val, _Size) __stosb((byte*)_Dst, (byte*)_Val, _Size)
#define memcpy(_Dst, _Src, _Size) __movsb((byte*)_Dst, (byte*)_Src, _Size)

// Standard Declarations
EXCEPTION_DISPOSITION __cdecl __C_specific_handler(_In_ EXCEPTION_RECORD* ExceptionRecord, _In_ void* EstablisherFrame, _Inout_ CONTEXT* ContextRecord, _Inout_ DISPATCHER_CONTEXT* DispatcherContext);
