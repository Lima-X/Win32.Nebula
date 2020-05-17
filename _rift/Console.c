#include "pch.h"
#include "_rift.h"

#define CON_SUCCESS (FOREGROUND_GREEN)                                           // 0b0010
#define CON_INFO  ((FOREGROUND_RED | FOREGROUND_GREEN) | FOREGROUND_BLUE)      // 0b0111
#define CON_WARNING ((FOREGROUND_RED | FOREGROUND_GREEN) | FOREGROUND_INTENSITY) // 0b1101
#define CON_ERROR   (FOREGROUND_RED | FOREGROUND_INTENSITY)                      // 0b1100

static DWORD WINAPI thConsoleTitle(_In_ PVOID pParam);
static HANDLE t_hCon;

BOOL fnAllocConsole() {
	BOOL bT = AllocConsole();
	if (bT) {
		CreateThread(0, 0, thConsoleTitle, 0, 0, 0);
		t_hCon = GetStdHandle(STD_OUTPUT_HANDLE);
	}

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

BOOL fnPrintF(PCWSTR pText, WORD wAttribute, ...) {
	va_list vaArg;
	va_start(vaArg, wAttribute);

	PVOID hBuf = HeapAlloc(g_hPH, HEAP_ZERO_MEMORY, (1 << 12));
	DWORD nBufLen;
	StringCchVPrintfW((STRSAFE_LPWSTR)hBuf, (1 << 12) / sizeof(WCHAR), pText, vaArg);
	StringCchLengthW((STRSAFE_PCNZWCH)hBuf, (1 << 12) / sizeof(WCHAR), (PUINT32)&nBufLen);
	SetConsoleTextAttribute(t_hCon, wAttribute);
	WriteConsoleW(t_hCon, hBuf, nBufLen, &nBufLen, 0);
	HeapFree(g_hPH, 0, hBuf);

	va_end(vaArg);
	return nBufLen;
}