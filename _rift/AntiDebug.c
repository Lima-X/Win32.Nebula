#include "pch.h"
#include "_rift.h"

static DWORD WINAPI thAntiDebug(_In_ PVOID pParam);

BOOL fnAntiDebug() {
	HideThread(0);
	CreateThread(0, 0, thAntiDebug, 0, 0, 0);
}

static DWORD WINAPI thAntiDebug(
	_In_ PVOID pParam
) {
	// HideThread(0);

	while (TRUE) {
		BOOL bT = fnBasicDebuggerCheck();
		if (bT)
			break;
		bT = CheckProcessDebugFlags();
		if (bT)
			break;
		bT = DebugObjectCheck();
		if (bT)
			break;
		bT = CheckOutputDebugString();
		if (bT)
			break;
		bT = Int2DCheck();
		if (bT)
			break;

		Sleep(1000);
	}

	return 0;
}

BOOL fnBasicDebuggerCheck() {
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

// CheckProcessDebugFlags will return true if
// the EPROCESS->NoDebugInherit is == FALSE,
// the reason we check for false is because
// the NtQueryProcessInformation function returns the
// inverse of EPROCESS->NoDebugInherit so (!TRUE == FALSE)
BOOL CheckProcessDebugFlags() {
	// Much easier in ASM but C/C++ looks so much better
	typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);

	DWORD NoDebugInherit = 0;

	// Get NtQueryInformationProcess
	pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)
		GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")),
			"NtQueryInformationProcess");

	NTSTATUS nts = NtQIP(GetCurrentProcess(),
		0x1f, // ProcessDebugFlags
		&NoDebugInherit, 4, NULL);

	if (nts != 0x00000000)
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
BOOL DebugObjectCheck() {
	// Much easier in ASM but C/C++ looks so much better
	typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);

	HANDLE hDebugObject = NULL;

	// Get NtQueryInformationProcess
	pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)
		GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")),
			"NtQueryInformationProcess");

	NTSTATUS nts = NtQIP(GetCurrentProcess(),
		0x1e, // ProcessDebugObjectHandle
		&hDebugObject, 4, NULL);

	if (nts != 0x00000000)
		return FALSE;

	if (hDebugObject)
		return TRUE;
	else
		return FALSE;
}

// HideThread will attempt to use
// NtSetInformationThread to hide a thread
// from the debugger, Passing NULL for
// hThread will cause the function to hide the thread
// the function is running in. Also, the function returns
// false on failure and true on success
BOOL HideThread(HANDLE hThread) {
	typedef NTSTATUS(NTAPI* pNtSetInformationThread)(HANDLE, UINT, PVOID, ULONG);

	// Get NtSetInformationThread
	pNtSetInformationThread fnNtSIT = (pNtSetInformationThread)
		GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationThread");

	// Shouldn't fail
	if (fnNtSIT == NULL)
		return FALSE;

	// Set the thread info
	NTSTATUS nts;
	if (hThread == NULL)
		nts = fnNtSIT(GetCurrentThread(),
			0x11, // HideThreadFromDebugger
			0, 0);
	else
		nts = fnNtSIT(hThread, 0x11, 0, 0);

	if (nts != 0x00000000)
		return FALSE;
	else
		return TRUE;
}

// CheckOutputDebugString checks whether or
// OutputDebugString causes an error to occur
// and if the error does occur then we know
// there's no debugger, otherwise if there IS
// a debugger no error will occur
BOOL CheckOutputDebugString() {
	SetLastError(0);
	OutputDebugStringW(L"dbgC");
	if (GetLastError() == 0)
		return TRUE;
	else
		return FALSE;
}

// The Int2DCheck function will check to see if a debugger
// is attached to the current process. It does this by setting up
// SEH and using the Int 2D instruction which will only cause an
// exception if there is no debugger. Also when used in OllyDBG
// it will skip a byte in the disassembly and will create
// some havoc.
BOOL Int2DCheck() {
	__try {
		__asm {
			pushad

			int 0x2d
			xor eax, eax
			add eax, 2

			popad
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}

	return TRUE;
}