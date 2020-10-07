#include "global.h"
#include <stdio.h>

#ifdef _DEBUG
#pragma region Direct Debugging (through Debugger)
void dbgTracePoint(
	_In_z_   const char* sz,
	_In_opt_             ...
) {
	// Check if Formating is required
	BOOLEAN b = FALSE;
	for (uint16 i = 0; sz[i] != NULL; i++) {
		if (sz[i] == '%')
			if (sz[i + 1] != '%') {
				b = TRUE; break;
			} else
				i++;
	}

	char* psz = (char*)VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!psz)
		return;

	size_t nLen = strlen(sz);
	// Format if needed
	if (b) {
		va_list va;
		va_start(va, sz);
		vsprintf_s(psz, 0x1000, sz, va);
		va_end(va);
	} else
		memcpy(psz, sz, nLen + 1);
	if (psz[nLen - 1] != '\n')
		*(word*)&psz[nLen] = '\n\0';

	OutputDebugStringA(psz);
	if (b)
		VirtualFree((void*)psz, NULL, MEM_RELEASE);
}

void dbgStatusAssert(
	_In_           status s,
	_In_     const char* sz,
	_In_opt_       ...
) {
	if (s < 0) {
		TracePoint(sz, s);
		RaiseException(s, EXCEPTION_NONCONTINUABLE, NULL, NULL);
	}
}
#pragma endregion

#pragma region Indirect Debugging (through Logging)
void dbgLog() {

}
#pragma endregion

#pragma region Utility Debugging
// Temporery DllInjector, this allows for JIT debugging which manualmapping can't really do
status InjectDllW(
	_In_z_ const wchar* szDll,
	_In_         dword  dwPid
) {
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (!hProc)
		return -1; // Failed to open target Process

	void* rpDllPath = VirtualAllocEx(hProc, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!rpDllPath)
		return -2; // Failed to allocate remote Memory
	if (!WriteProcessMemory(hProc, rpDllPath, szDll, wcslen(szDll), NULL))
		return -3; // Failed to write to remote Memory

	void* pLoadLibraryW = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
	if (!pLoadLibraryW)
		return -4; // Failed to get Loaderfunctionaddress
	HANDLE hRemoteThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW, rpDllPath, NULL, NULL);
	if (!hRemoteThread)
		return -5; // Failed to create remote Thread

	WaitForSingleObject(hRemoteThread, INFINITE);
	dword dwRemote;
	GetExitCodeThread(hRemoteThread, &dwRemote);

	CloseHandle(hRemoteThread);
	VirtualFreeEx(hProc, rpDllPath, 0, MEM_RELEASE);
	CloseHandle(hProc);
	return dwRemote;
}
#pragma endregion
#endif
