#include "pch.h"
#include "_rift.h"

BOOL fnAntiDllInject() {

}

const static PCWSTR szAllowedModules[] = {
	L"ntdll.dll",
	L"user32.dll",
	L""
};
#define nAllowedModules (sizeof(szAllowedModules) / sizeof(*szAllowedModules))

BOOL fnCheckModules() {
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());
	if (!hProcess)
		return 1;

	// Get a list of all the modules in this process.
	DWORD nResult;
	BOOL bs = K32EnumProcessModules(hProcess, 0, 0, &nResult);
	HMODULE* hMods = (HMODULE*)HeapAlloc(g_hPH, 0, nResult);
	bs = K32EnumProcessModules(hProcess, hMods, sizeof(hMods), &nResult);
	if (bs)
		for (UINT8 i = 0; i < (nResult / sizeof(HMODULE)); i++) {
			WCHAR szModName[MAX_PATH];

			// Get the full path to the module's file.
			if (K32GetModuleFileNameExW(hProcess, hMods[i], szModName, MAX_PATH)) {

			}
		}

	HeapFree(g_hPH, 0, hMods);
	CloseHandle(hProcess);

	return 0;
}