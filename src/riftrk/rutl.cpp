#include "rk.h"

#ifdef _DEBUG
static PTOP_LEVEL_EXCEPTION_FILTER OldFilter;

status CreateDumpEx(                           // Wrapper for dumpfiledirectory autocreation
	_In_opt_ EXCEPTION_POINTERS* ExceptionInfo // See CreateDump (dbg::CreateDump)
) {
	auto Path = L"C:\\Win32.Nebula\\Minidumps";
	if (GetFileAttributesW(Path) == INVALID_FILE_ATTRIBUTES)
		if (GetLastError() == ERROR_PATH_NOT_FOUND)
			utl::CreatePath(Path);
		else
			return S_CREATE(SS_ERROR, SF_ROOTKIT, SC_UNKNOWN);
	return CreateDump(Path, ExceptionInfo);
}

// Incase an Exception occurs this will immediately catch it
// and check if the Exception originates from this Module,
// incase it does it will create a Minidumpfile and Terminate,
// otherwise it pass control to Higher Level Filters.
long __stdcall VMinidumpExceptionFilter(
	_In_ EXCEPTION_POINTERS* ExceptionInfo
) {
	// Check if Expection occurred within Rootkit-Module
	ptr ExceptionAddress = (ptr)ExceptionInfo->ExceptionRecord->ExceptionAddress;
	size_t ModuleSize = utl::GetNtHeader((HMODULE)g_BaseAddress)->OptionalHeader.SizeOfImage;
	if (ExceptionAddress <= (ptr)g_BaseAddress
		|| ExceptionAddress >= (ptr)g_BaseAddress + ModuleSize)
	return EXCEPTION_CONTINUE_SEARCH;

	CreateDumpEx(ExceptionInfo);
	__fastfail((u32)-1);
	return - 1;
}
// Incase an Excpetion makes it past the VectoredHandlers and the Process Specific ones
// this Handler will call the original UnHandlerExceptionFilter and respond to its returnvalue
long __stdcall UhMinidumpExceptionFilter(
	_In_ EXCEPTION_POINTERS* ExceptionInfo
) {
	if (OldFilter) {
		long s = OldFilter(ExceptionInfo);
		if (s == EXCEPTION_CONTINUE_SEARCH)
			CreateDumpEx(ExceptionInfo);
		return s;
	} else
		CreateDumpEx(ExceptionInfo);
	return 0;
}

status RegisterMinidump() {
	OldFilter = SetUnhandledExceptionFilter(UhMinidumpExceptionFilter);
	void* v0 = AddVectoredExceptionHandler(true, VMinidumpExceptionFilter);
	return !v0;
}
#endif
