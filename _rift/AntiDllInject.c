#include "pch.h"
#include "_rift.h"

BOOL fnAntiDllInject() {

}

static PCWSTR l_szAllowedModules[] = {
	L"kernel32.dll",
	L"ntdll.dll",
	L"user32.dll",
	L"msvcrt.dll"
};
#define nAllowedModules (sizeof(l_szAllowedModules) / sizeof(PCWSTR))

BOOL fnCheckModules() {
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());
	if (!hProcess)
		return 1;

	// Get a list of all the modules in this process.
	DWORD nResult;
	BOOL bs = K32EnumProcessModules(hProcess, 0, 0, &nResult);
	HMODULE* hMods = (HMODULE*)fnMalloc(nResult, 0);
	bs = K32EnumProcessModules(hProcess, hMods, sizeof(hMods), &nResult);
	if (bs)
		for (UINT8 i = 0; i < (nResult / sizeof(HMODULE)); i++) {
			WCHAR szModName[MAX_PATH];

			// Get the full path to the module's file.
			if (K32GetModuleFileNameExW(hProcess, hMods[i], szModName, MAX_PATH)) {

			}
		}

	fnFree(hMods, 0);
	CloseHandle(hProcess);

	return 0;
}