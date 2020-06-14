#include "pch.h"
#include "_rift.h"

BOOL IAntiDllInject() {

}

static PCWSTR l_szAllowedModules[] = {
	L"kernel32.dll",
	L"ntdll.dll",
	L"user32.dll",
	L"msvcrt.dll"
};
DWORD WINAPI thCheckModules(
	_In_ PVOID pParam
) {
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());
	if (hProcess == INVALID_HANDLE_VALUE)
		return FALSE;

	// Get a list of all the modules in this process.
	DWORD nResult;
	BOOL bs = K32EnumProcessModules(hProcess, 0, 0, &nResult);
	HMODULE* hMods = (HMODULE*)AllocMemory(nResult, 0);
	bs = K32EnumProcessModules(hProcess, hMods, sizeof(hMods), &nResult);
	if (bs)
		for (UINT8 i = 0; i < nResult / sizeof(HMODULE); i++) {
			WCHAR szModuleName[MAX_PATH];

			// Get the full path to the module's file.
			if (K32GetModuleFileNameExW(hProcess, hMods[i], szModuleName, MAX_PATH)) {

			}
		}

	FreeMemory(hMods);
	CloseHandle(hProcess);

	return 0;
}

/* Hook LoadLibrary/Ex to prevent native Dll Injection.
   Can be bypassed by Manual Mapping! */
static PCWSTR l_AllowedLibraries[] = {
	L""
};
static HMODULE(WINAPI* RLoadLibraryW)(_In_ LPCWSTR lpLibFileName) = LoadLibraryW;
HMODULE WINAPI HLoadLibraryW(_In_ LPCWSTR lpLibFileName) {
	for (UINT8 i = 0; i < sizeof(l_AllowedLibraries) / sizeof(PCWSTR); i++)
		if (!StrStrIW(lpLibFileName, l_AllowedLibraries[i]))
			return RLoadLibraryW(lpLibFileName);
	return 0;
}
static HMODULE(WINAPI* RLoadLibraryExW)(_In_ LPCWSTR lpLibFileName, _Reserved_ HANDLE hFile, _In_ DWORD dwFlags) = LoadLibraryExW;
HMODULE WINAPI HLoadLibraryExW(_In_ LPCWSTR lpLibFileName, _Reserved_ HANDLE hFile, _In_ DWORD dwFlags) {
	for (UINT8 i = 0; i < sizeof(l_AllowedLibraries) / sizeof(PCWSTR); i++)
		if (!StrStrIW(lpLibFileName, l_AllowedLibraries[i]))
			return RLoadLibraryExW(lpLibFileName, hFile, dwFlags);
	return 0;
}
BOOL IHookLoadLibrary() {
	if (DetourTransactionBegin())
		goto EXIT;

	// Update all Threads
	HANDLE hTSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hTSnap == INVALID_HANDLE_VALUE)
		goto EXIT;
	THREADENTRY32 te; te.dwSize = sizeof(te);
	HANDLE hThread[0x20]; // Allocate Dynamically in the future
	UINT8 nThread = 0;
	if (Thread32First(hTSnap, &te)) {
		do {
			hThread[nThread] = OpenThread(THREAD_ALL_ACCESS, 0, te.th32ThreadID);
			DetourUpdateThread(hThread[nThread]);
			nThread++;
		} while (Thread32Next(hTSnap, &te));
	} else {
		CloseHandle(hTSnap);
		goto EXIT;
	}

	// Detour LoadLibrary Functions
	DetourAttach(&LoadLibraryW, HLoadLibraryW);
	DetourAttach(&LoadLibraryExW, HLoadLibraryExW);
	DetourTransactionCommit();

	// CleanUp
	for (UINT8 i = 0; i < nThread; i++)
		CloseHandle(hThread[i]);
	CloseHandle(hTSnap);
	return TRUE;

EXIT:
	DetourTransactionAbort();
	return FALSE;
}