#include "pch.h"
#include "_rift.h"

typedef BOOL(*pfnDllInit)();

/*
WCHAR g_wcsMFN[MAX_PATH];
WCHAR g_wcsCD[MAX_PATH];
HMODULE g_hmMH;
HANDLE g_hPH;
*/

INT WINAPI wWinMain(
	_In_     HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_     PWSTR     pCmdLine,
	_In_     INT       nCmdShow
) {
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(nCmdShow);
	g_hmMH = hInstance;
	GetModuleFileNameW(hInstance, g_wcsMFN, sizeof(g_wcsMFN) / sizeof(*g_wcsMFN));
	GetCurrentDirectoryW(sizeof(g_wcsCD) / sizeof(*g_wcsCD), g_wcsCD);
	g_hPH = GetProcessHeap();

	BOOL bRE = fnAntiRE();
	BOOL bVM = fnCheckVMPresent();

	fnAllocConsole();

	HMODULE hDll = LoadLibraryExW(L"_riftdll.dll", 0, LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
	if (!hDll)
		return 2;

	pfnDllInit fnDllInit = (pfnDllInit)GetProcAddress(hDll, "fnDllInit");

	FreeLibrary(hDll);
	return 0;
}