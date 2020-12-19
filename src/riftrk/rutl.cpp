#include "rk.h"

#ifdef _DEBUG
// #pragma comment(lib, "dbghelp.lib")
#include <dbghelp.h>

IMAGE_NT_HEADERS* GetNtHeader(
	_In_ HMODULE hMod
) {
	IMAGE_NT_HEADERS* NtHeader = (IMAGE_NT_HEADERS*)((ptr)hMod + ((IMAGE_DOS_HEADER*)hMod)->e_lfanew);
	if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
		return nullptr; // Invalid Signature
	if (NtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
		return nullptr; // Invalid Signature

	return NtHeader;
}

void CreateDump(
	_In_ EXCEPTION_POINTERS* ExceptionInfo
) {
	wchar MiniDumpFile[MAX_PATH];
	auto NT = utl::GetModuleHandleByHash(N_NTDLL);
	auto func = utl::ImportFunctionByHash(NT, utl::FNV1aHash((void*)"swprintf", 8));

	((int(*)(wchar*, size_t, const wchar*, ...))func)
		(MiniDumpFile, MAX_PATH, L"C:\\rift\\MiniDumps\\riftrk\\PId_%d.dmp", GetCurrentProcessId());

	// Create Dumpfile and Allocate Directory if necessary
	HANDLE hFile = CreateFileW(MiniDumpFile, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ, nullptr, CREATE_ALWAYS, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		CreateDirectoryW(L"C:\\rift", nullptr);
		CreateDirectoryW(L"C:\\rift\\MiniDumps", nullptr);
		CreateDirectoryW(L"C:\\rift\\MiniDumps\\riftrk", nullptr);
		hFile = CreateFileW(MiniDumpFile, GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ, nullptr, CREATE_ALWAYS, NULL, NULL);
	}

	// Load and Get MiniDumpWriteDump Function
	HMODULE hDbg = LoadLibraryW(L"dbghelp.dll");
	typedef BOOL(__stdcall* MDWD_t)(
		_In_ HANDLE hProcess,
		_In_ DWORD ProcessId,
		_In_ HANDLE hFile,
		_In_ MINIDUMP_TYPE DumpType,
		_In_opt_ PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
		_In_opt_ PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
		_In_opt_ PMINIDUMP_CALLBACK_INFORMATION CallbackParam
	);
	MDWD_t MiniDumpWriteDump = (MDWD_t)GetProcAddress(hDbg, "MiniDumpWriteDump");

	// Create and Write Minidump
	MINIDUMP_EXCEPTION_INFORMATION mdei;
	mdei.ExceptionPointers = ExceptionInfo;
	mdei.ThreadId = GetCurrentThreadId();
	mdei.ClientPointers = false;
	MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile,
		MiniDumpNormal, &mdei, nullptr, nullptr);

	// Free Debughelp and commit MiniDump
	FreeLibrary(hDbg);
	FlushFileBuffers(hFile);
	CloseHandle(hFile);
}

static PTOP_LEVEL_EXCEPTION_FILTER OldFilter;

// Incase an Exception occurs this will immediately catch it
// and check if the Exception originates from this Module,
// incase it does it will create a Minidumpfile and Terminate,
// otherwise it pass control to Higher Level Filters.
long __stdcall VMinidumpExceptionFilter(
	_In_ EXCEPTION_POINTERS* ExceptionInfo
) {
	// Check if Expection occurred within Rootkit-Module
	ptr ExceptionAddress = (ptr)ExceptionInfo->ExceptionRecord->ExceptionAddress;
	size_t ModuleSize = GetNtHeader((HMODULE)g_BaseAddress)->OptionalHeader.SizeOfImage;
	if (ExceptionAddress <= (ptr)g_BaseAddress
		|| ExceptionAddress >= (ptr)g_BaseAddress + ModuleSize)
	return EXCEPTION_CONTINUE_SEARCH;

	CreateDump(ExceptionInfo);
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
			CreateDump(ExceptionInfo);
		return s;
	} else
		CreateDump(ExceptionInfo);
	return 0;
}

status RegisterMinidump() {
	OldFilter = SetUnhandledExceptionFilter(UhMinidumpExceptionFilter);
	void* v0 = AddVectoredExceptionHandler(true, VMinidumpExceptionFilter);
	return !v0;
}
#endif
