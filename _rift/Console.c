#include "pch.h"
#include "_rift.h"

const static WCHAR szConsoleTitle[] = L"[_rift-Loader] by Lima X [L4X]";
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

VOID fnCLS(
	_In_ HANDLE hConsole
) {
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	if (!GetConsoleScreenBufferInfo(hConsole, &csbi))
		return;

	DWORD dwConSize = csbi.dwSize.X * csbi.dwSize.Y;
	COORD coordScreen = { 0, 0 };
	DWORD cCharsWritten;
	if (!FillConsoleOutputCharacterW(hConsole, L' ', dwConSize, coordScreen, &cCharsWritten))
		return;

	if (!GetConsoleScreenBufferInfo(hConsole, &csbi))
		return;

	if (!FillConsoleOutputAttribute(hConsole, csbi.wAttributes, // Character attributes to use
		dwConSize,        // Number of cells to set attribute
		coordScreen,      // Coordinates of first cell
		&cCharsWritten)) // Receive number of characters written
	{
		return;
	}

	// Put the cursor at its home coordinates.
	SetConsoleCursorPosition(hConsole, coordScreen);
}