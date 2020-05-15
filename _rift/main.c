#include "pch.h"
#include "_rift.h"

typedef BOOL(*pfnDllInit)(pEpTDll pData);

WCHAR g_wcsMFN[MAX_PATH];
WCHAR g_wcsCD[MAX_PATH];
HMODULE g_hmCM;
HANDLE g_hPH;

INT WINAPI wWinMain(
	_In_     HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_     PWSTR     pCmdLine,
	_In_     INT       nCmdShow
) {
	g_hmCM = hInstance;
	GetModuleFileNameW(hInstance, g_wcsMFN, sizeof(g_wcsMFN) / sizeof(*g_wcsMFN));
	GetCurrentDirectoryW(sizeof(g_wcsCD) / sizeof(*g_wcsCD), g_wcsCD);
	g_hPH = GetProcessHeap();

	fnAntiRE();
	BOOL bVM = fnCheckVMPresent();


	sEpTDll sData;
	sData.g_wcsMFN = &g_wcsMFN;
	sData.g_wcsCD = &g_wcsCD;
	sData.pfnXorEncrypt = fnXorEncrypt;
	sData.pfnXorEncrypt = fnXorDecrypt;



	fnAllocConsole();




	HMODULE hDll = LoadLibraryExW(L"_riftdll.dll", 0, LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
	if (!hDll)
		return 2;

	pfnDllInit fnDllInit = (pfnDllInit)GetProcAddress(hDll, "fnDllInit");
	fnDllInit(&sData);

	FreeLibrary(hDll);


	Sleep(10000);
	return 0;
}