#include "nrt.h"

typedef EXCEPTION_DISPOSITION(__cdecl* __C_SPECIFIC_HANDLER_t)(
	_In_    EXCEPTION_RECORD*   ExceptionRecord,
	_In_    void*               EstablisherFrame,
	_Inout_ CONTEXT*            ContextRecord,
	_Inout_ DISPATCHER_CONTEXT* DispatcherContext
);

static __C_SPECIFIC_HANDLER_t ExceptionHandler;
EXCEPTION_DISPOSITION __cdecl __C_specific_handler(
	_In_    EXCEPTION_RECORD*   ExceptionRecord,
	_In_    void*               EstablisherFrame,
	_Inout_ CONTEXT*            ContextRecord,
	_Inout_ DISPATCHER_CONTEXT* DispatcherContext
) {
	if (ExceptionHandler)
		return ExceptionHandler(ExceptionRecord, EstablisherFrame, ContextRecord, DispatcherContext);
	HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
	ExceptionHandler = (__C_SPECIFIC_HANDLER_t)GetProcAddress(hNtDll, "__C_specific_handler");
	if (!ExceptionHandler)
		__fastfail((u32)S_CREATE(SS_ERROR, SF_NULL, SC_INVALID_POINTER));
	return ExceptionHandler(ExceptionRecord, EstablisherFrame, ContextRecord, DispatcherContext);
}

// Allocators for Objects
void* __cdecl operator new(size_t size) {
	return HeapAlloc(GetProcessHeap(), NULL, size);
}
void __cdecl operator delete(void* mem) {
	HeapFree(GetProcessHeap(), NULL, mem);
}

namespace nrt {
	size_t strlen(
		_In_z_ const char* sz
	) {
		size_t Length = 0;
		while (*sz++)
			Length++;
		return Length;
	}
	size_t wcslen(
		_In_z_ const wchar* sz
	) {
		size_t Length = 0;
		while (*sz++)
			Length++;
		return Length;
	}
}
