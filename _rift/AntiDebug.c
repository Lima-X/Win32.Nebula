#include "pch.h"
#include "_rift.h"

static HMODULE hNtDll;

// Rewrite: Do it manually, by reading the flag directly from the PEB
static BOOL IBasicDebuggerCheck() {
	BOOL bT = IsDebuggerPresent();
	if (!bT) {
		BOOL bDP;
		bT = CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDP);
		if (bT)
			return bDP;
		else
			return FALSE;
	} else
		return bT;
}

// ICheckProcessDebugFlags will return true if
// the EPROCESS->NoDebugInherit is == FALSE,
// the reason we check for false is because
// the NtQueryProcessInformation function returns the
// inverse of EPROCESS->NoDebugInherit so (!TRUE == FALSE)
static BOOL ICheckProcessDebugFlags() {
	// Much easier in ASM but C/C++ looks so much better
	typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);

	// Get NtQueryInformationProcess
	pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");

	DWORD NoDebugInherit;
	NTSTATUS nts = NtQIP(GetCurrentProcess(),
		0x1f, // ProcessDebugFlags
		&NoDebugInherit, 4, 0);

	if (!nts)
		return FALSE;

	if (NoDebugInherit == FALSE)
		return TRUE;
	else
		return FALSE;
}

// This function uses NtQuerySystemInformation
// to try to retrieve a handle to the current
// process's debug object handle. If the function
// is successful it'll return true which means we're
// being debugged or it'll return false if it fails
// or the process isn't being debugged
static BOOL IDebugObjectCheck() {
	// Much easier in ASM but C/C++ looks so much better
	typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);

	// Get NtQueryInformationProcess
	pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");

	HANDLE hDebugObject;
	NTSTATUS nts = NtQIP(GetCurrentProcess(),
		0x1e, // ProcessDebugObjectHandle
		&hDebugObject, 4, 0);

	if (!nts)
		return FALSE;

	if (hDebugObject)
		return TRUE;
	else
		return FALSE;
}

// EHideThread will attempt to use
// NtSetInformationThread to hide a thread
// from the debugger, Passing NULL for
// hThread will cause the function to hide the thread
// the function is running in. Also, the function returns
// false on failure and true on success
static BOOL EHideThread(HANDLE hThread) {
	typedef NTSTATUS(NTAPI* pNtSetInformationThread)(HANDLE, UINT, PVOID, ULONG);

	// Get NtSetInformationThread
	pNtSetInformationThread fnNtSIT = (pNtSetInformationThread)GetProcAddress(hNtDll, "NtSetInformationThread");

	// Shouldn't fail
	if (!fnNtSIT)
		return FALSE;

	// Set the thread info
	NTSTATUS nts;
	if (!hThread)
		nts = fnNtSIT(GetCurrentThread(),
			0x11, // HideThreadFromDebugger
			0, 0);
	else
		nts = fnNtSIT(hThread, 0x11, 0, 0);

	if (!nts)
		return FALSE;
	else
		return TRUE;
}

// ICheckOutputDebugString checks whether or
// OutputDebugString causes an error to occur
// and if the error does occur then we know
// there's no debugger, otherwise if there IS
// a debugger no error will occur
static BOOL ICheckOutputDebugString() {
	SetLastError(0);
	OutputDebugStringW(L"dbgC");
	if (!GetLastError())
		return TRUE;
	else
		return FALSE;
}

// The IInt2DCheck function will check to see if a debugger
// is attached to the current process. It does this by setting up
// SEH and using the Int 2D instruction which will only cause an
// exception if there is no debugger. Also when used in OllyDBG
// it will skip a byte in the disassembly and will create
// some havoc.
static BOOL IInt2DCheck() {
	__try {
		__asm {
			int 0x2d
			xor eax, eax
			add eax, 2
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}

	return TRUE;
}

//// The function will attempt to open csrss.exe with
//// PROCESS_ALL_ACCESS rights if it fails we're
//// not being debugged however, if its successful we probably are
//static BOOL ITryOpenCsrss() {
//	// If we're being debugged and the process has
//	// SeDebugPrivileges privileges then this call
//	// will be successful, note that this only works
//	// with PROCESS_ALL_ACCESS.
//
//	// Grab the export from NtDll
//	typedef HANDLE(NTAPI* pfnCsrGetProcessId)();
//	pfnCsrGetProcessId CsrGetProcessId = (pfnCsrGetProcessId)GetProcAddress(hNtDll, "CsrGetProcessId");
//	DWORD dwCsrss = CsrGetProcessId();
//	PDWORD pCsrss = &dwCsrss;
//
//	SIZE_T nProcesses = 1;
//	if (!dwCsrss)
//		pCsrss = EGetProcessIdbyName(L"csrss.exe", &nProcesses);
//
//	BOOL bT = FALSE;
//	for (UINT i = 0; i < nProcesses; i++) {
//		HANDLE hCsrss = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pCsrss[i]);
//		if (hCsrss) {
//			bT = TRUE;
//			CloseHandle(hCsrss);
//			break;
//		}
//	}
//
//	if (!dwCsrss)
//		FreeMemory(pCsrss);
//
//	return bT;
//}
//

// CheckCloseHandle will call CloseHandle on an invalid
// DWORD aligned value and if a debugger is running an exception
// will occur and the function will return true otherwise it'll
// return false
static BOOL ICheckCloseHandle() {
	__try {
		CloseHandle(0x8000);
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return TRUE;
	}

	return FALSE;
}

LONG WINAPI IUnhandledExcepFilter(PEXCEPTION_POINTERS pExcepPointers) {
	// Restore old UnhandledExceptionFilter
	SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)pExcepPointers->ContextRecord->Eax);

	// Skip the exception code
	pExcepPointers->ContextRecord->Eip += 2;

	return EXCEPTION_CONTINUE_EXECUTION;
}
VOID ISehUnhandledException() {
	SetUnhandledExceptionFilter(IUnhandledExcepFilter);
	__asm {
		xor eax, eax
		div eax
	}

	// Execution resumes here if there is no debugger
	// or if there is a debugger it will never
	// reach this point of execution
}

static DWORD WINAPI thAntiDebug(_In_ PVOID pParam);
BOOL IAntiDebug() {
	hNtDll = GetModuleHandleW(L"ntdll.dll");
	EHideThread(0);
//	ITryOpenCsrss();
	CreateThread(0, 0, thAntiDebug, 0, 0, 0);
}

static DWORD WINAPI thAntiDebug(
	_In_ PVOID pParam
) {
	EHideThread(0);

	while (TRUE) {
		BOOL bT = IBasicDebuggerCheck();
		if (bT)	break;
		bT = ICheckProcessDebugFlags();
		if (bT) break;
		bT = IDebugObjectCheck();
		if (bT) break;
		bT = ICheckOutputDebugString();
		if (bT) break;
		bT = IInt2DCheck();
		if (bT) break;
		bT = ICheckCloseHandle();
		if (bT) break;

		Sleep(1000);
	}

	return 0;
}