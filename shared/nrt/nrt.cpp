#include "nrt.h"

#ifdef R_RIFTLDR
#pragma code_seg(".ldr")
#pragma data_seg(".ldrd")
#pragma const_seg(".ldrc")
#endif
typedef EXCEPTION_DISPOSITION(__cdecl* __C_SPECIFIC_HANDLER_t)(
	_In_    EXCEPTION_RECORD*   ExceptionRecord,
	_In_    void*               EstablisherFrame,
	_Inout_ CONTEXT*            ContextRecord,
	_Inout_ DISPATCHER_CONTEXT* DispatcherContext
);

#ifdef R_RIFTLDR
#pragma section(".ldrd")
__declspec(allocate(".ldrd"))
#endif
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
		__fastfail((u32)M_CREATE(S_ERROR, F_NULL, C_INVALID_POINTER));
	return ExceptionHandler(ExceptionRecord, EstablisherFrame, ContextRecord, DispatcherContext);
}
#ifdef R_RIFTLDR
#pragma const_seg()
#pragma data_seg()
#pragma code_seg()
#endif
