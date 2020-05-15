#include "pch.h"
#include "_rift.h"

const static WCHAR szConsoleTitle[] = L"Win32._rift by Lima X [L4X]";
const static UINT8 nConsoleTitleLen = sizeof(szConsoleTitle) / sizeof(WCHAR);
static DWORD WINAPI thConsoleTitle(_In_ PVOID pParam);

BOOL fnAllocConsole() {
	BOOL bT = AllocConsole();
	if (bT)
		CreateThread(0, 0, thConsoleTitle, 0, 0, 0);

	return bT;
}

static DWORD WINAPI thConsoleTitle(
	_In_ PVOID pParam
) {
	PVOID pBuffer = 0;
	PWCHAR pTitleBuf = HeapAlloc(g_hPH, HEAP_ZERO_MEMORY, nConsoleTitleLen * sizeof(WCHAR));
	if (pTitleBuf)
		for (UINT8 i = 0; i < nConsoleTitleLen; i++) {
			pTitleBuf[i] = szConsoleTitle[i];
			SetConsoleTitleW(pTitleBuf);
			Sleep(50);
		}

	return 0;
}