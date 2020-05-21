#include "pch.h"
#include "_rift.h"

typedef BOOL(*pfnDllInit)();

INT WINAPI wWinMain(
	_In_     HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_     PWSTR     pCmdLine,
	_In_     INT       nCmdShow
) {
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(nCmdShow);
	g_hmMH = hInstance;
	GetModuleFileNameW(hInstance, g_szMFN, sizeof(g_szMFN) / sizeof(*g_szMFN));
	GetCurrentDirectoryW(sizeof(g_szCD) / sizeof(*g_szCD), g_szCD);
	g_hPH = GetProcessHeap();

	// BOOL bRE = fnAntiRE();
	// BOOL bVM = fnCheckVMPresent();

	fnAllocConsole();

	fnUnpackResource(L"_rift.KEY", L"a", IDR_RIFTDLL);
	HMODULE hDll = LoadLibraryExW(L"_riftdll.dll", 0, LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
	if (!hDll)
		return 2;

	pfnDllInit fnDllInit = (pfnDllInit)GetProcAddress(hDll, "fnDllInit");

	FreeLibrary(hDll);
	return 0;
}